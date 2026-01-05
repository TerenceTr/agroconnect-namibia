# ====================================================================
# backend/socketio/namespaces.py — Socket.IO Namespaces (PRODUCTION)
# ====================================================================
# FILE ROLE:
#   • Defines all Socket.IO namespaces for AgroConnect
#   • Enforces refresh-token authentication (NOT access tokens)
#   • Applies role-based access control (admin room + admin namespace)
#   • Presence tracking + rate limiting hooks
#
# KEY ASSUMPTION:
#   User exposes:
#     • user.is_admin   (bool @property)
#     • user.role_name  ("admin"/"farmer"/"customer")
# ====================================================================

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional, Protocol, cast

from flask_socketio import join_room  # type: ignore[attr-defined]
from flask_socketio.namespace import Namespace

from backend.database.db import db
from backend.models.user import User
from backend.utils.jwt_utils import jwt_decode
from backend.utils.presence import mark_active, mark_offline, mark_online
from backend.utils.socketio_rate_limit import allow_event

logger = logging.getLogger("agroconnect.socketio")


# --------------------------------------------------------------------
# Minimal Socket.IO typing shim
# --------------------------------------------------------------------
class SocketIOProtocol(Protocol):
    def on_namespace(self, namespace: Namespace) -> None: ...
    def emit(self, event: str, data: Any, **kwargs: Any) -> None: ...


def _to_uuid(value: Any) -> Optional[uuid.UUID]:
    """Parse UUID from any input; return None if invalid."""
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


# ====================================================================
# AUTHENTICATION (REFRESH TOKEN ONLY)
# ====================================================================
def _auth_user(auth: Optional[Dict[str, Any]]) -> Optional[User]:
    """
    Authenticate Socket.IO connection using refresh token ONLY.

    Client may send:
      • auth.refresh_token
      • auth.refreshToken

    JWT payload must be refresh:
      • payload.purpose == "refresh"  (preferred)
      • payload.type    == "refresh"  (legacy)
    """
    if not isinstance(auth, dict):
        return None

    token = auth.get("refresh_token") or auth.get("refreshToken")
    if not isinstance(token, str) or not token.strip():
        return None

    try:
        payload = jwt_decode(token)

        purpose = payload.get("purpose") or payload.get("type")
        if purpose != "refresh":
            return None

        sub = payload.get("sub")
        user_uuid = _to_uuid(sub)
        if user_uuid is None:
            return None

        user = db.session.get(User, user_uuid)
        if not user or not bool(getattr(user, "is_active", True)):
            return None

        return user

    except Exception as exc:
        logger.warning("[SocketIO] Auth failed: %s", exc)
        return None


# ====================================================================
# BASE AUTHENTICATED NAMESPACE
# ====================================================================
class AuthedNamespace(Namespace):
    """
    Base namespace enforcing:
      • refresh-token authentication
      • presence tracking
      • heartbeat updates
    """

    user: Optional[User]
    ns_name: str

    def __init__(self, namespace: str):
        super().__init__(namespace)
        self.ns_name = namespace
        self.user = None

    def _require_user(self, auth: Optional[Dict[str, Any]]) -> Optional[User]:
        user = _auth_user(auth)
        if not user:
            logger.info("[SocketIO] Unauthorized (%s)", self.ns_name)
            return None

        self.user = user
        mark_online(str(user.id))
        return user

    def on_disconnect(self):
        if self.user:
            mark_offline(str(self.user.id))
            logger.info("[SocketIO] User %s disconnected (%s)", self.user.id, self.ns_name)

    def on_heartbeat(self):
        """Client heartbeat (emit every ~10s)."""
        if self.user:
            mark_active(str(self.user.id))


# ====================================================================
# ROOT NAMESPACE "/"
# ====================================================================
class RootNamespace(AuthedNamespace):
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        user = self._require_user(auth)
        if not user:
            return False

        self.emit(
            "connected",
            {"message": "Connected to AgroConnect realtime API", "user": user.to_dict()},
        )

    def on_ping_server(self, data: Any = None):
        self.emit("pong", {"ok": True, "payload": data})


# ====================================================================
# NOTIFICATIONS "/notifications"
# ====================================================================
class NotificationsNamespace(AuthedNamespace):
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        user = self._require_user(auth)
        if not user:
            return False

        join_room(f"user:{user.id}")

        # Admin broadcast room
        if user.is_admin:
            join_room("admins")

        self.emit("notify_connected", {"user": user.to_dict()})

    def on_subscribe(self, data: Dict[str, Any]):
        if not self.user:
            return

        # Rate limit uses role_name (admin/farmer/customer)
        if not allow_event(key=f"notify:{self.user.id}", role=self.user.role_name, window=10):
            self.emit("error", {"error": "Rate limit exceeded"})
            return

        topic = str(data.get("topic") or "").strip()
        if not topic:
            self.emit("error", {"error": "topic required"})
            return

        join_room(f"topic:{topic}")
        self.emit("subscribed", {"topic": topic})


# ====================================================================
# CHAT "/chat"
# ====================================================================
class ChatNamespace(AuthedNamespace):
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        user = self._require_user(auth)
        if not user:
            return False
        self.emit("chat_connected", {"user": user.to_dict()})

    def on_message(self, data: Dict[str, Any]):
        if not self.user:
            return

        if not allow_event(key=f"chat:{self.user.id}", role=self.user.role_name, window=10):
            self.emit("error", {"error": "Rate limit exceeded"})
            return

        text = data.get("text")
        if not isinstance(text, str) or not text.strip():
            self.emit("error", {"error": "Invalid message schema"})
            return

        self.emit("message", {"text": text.strip()})


# ====================================================================
# ADMIN "/admin"
# ====================================================================
class AdminNamespace(AuthedNamespace):
    def on_connect(self, auth: Optional[Dict[str, Any]] = None):
        user = self._require_user(auth)
        if not user or not user.is_admin:
            return False

        join_room("admins")
        self.emit("admin_connected", {"user": user.to_dict()})

    def on_admin_ping(self, data: Any = None):
        self.emit("admin_pong", {"ok": True, "payload": data})


# ====================================================================
# REGISTRATION
# ====================================================================
def register_namespaces(socketio_obj: Any) -> None:
    """Register all Socket.IO namespaces."""
    sio = cast(SocketIOProtocol, socketio_obj)

    sio.on_namespace(RootNamespace("/"))
    sio.on_namespace(NotificationsNamespace("/notifications"))
    sio.on_namespace(ChatNamespace("/chat"))
    sio.on_namespace(AdminNamespace("/admin"))
