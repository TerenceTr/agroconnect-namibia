from __future__ import annotations

import logging
from typing import Any, Optional
from uuid import UUID

from flask import request
from flask_socketio import emit, join_room

from backend.database.db import db
from backend.extensions import socketio
from backend.models.user import User
from backend.utils.jwt_utils import jwt_decode

logger = logging.getLogger("agroconnect.socketio.realtime")


def _to_uuid(value: Any) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except Exception:
        return None


def _extract_token(auth: Any) -> str:
    if not isinstance(auth, dict):
        return ""
    for key in ("token", "access_token", "accessToken", "refresh_token", "refreshToken"):
        value = auth.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def authenticate_socket_user(auth: Any) -> Optional[User]:
    token = _extract_token(auth)
    if not token:
        return None

    try:
        payload = jwt_decode(token)
    except Exception as exc:
        logger.warning("[Socket.IO] token decode failed: %s", exc)
        return None

    purpose = str(payload.get("purpose") or payload.get("type") or "").strip().lower()
    if purpose not in {"access", "refresh"}:
        return None

    user_id = _to_uuid(payload.get("sub") or payload.get("user_id") or payload.get("id"))
    if user_id is None:
        return None

    user = db.session.get(User, user_id)
    if not isinstance(user, User):
        return None

    if not bool(getattr(user, "is_active", True)):
        return None

    return user


@socketio.on("connect")
def handle_connect(auth: Any = None):
    user = authenticate_socket_user(auth)
    if not user:
        logger.info("[Socket.IO] rejected anonymous connection")
        return False

    join_room(f"user:{user.id}")

    role_name = str(getattr(user, "role_name", "") or "").strip().lower()
    if role_name:
        join_room(f"role:{role_name}")

    emit(
        "messages:connected",
        {
            "ok": True,
            "user_id": str(user.id),
            "sid": getattr(request, "sid", None),
        },
    )
    logger.info("[Socket.IO] user %s connected", user.id)


@socketio.on("messages:ping")
def handle_messages_ping(data: Any = None):
    emit("messages:pong", {"ok": True, "payload": data or {}})


@socketio.on("disconnect")
def handle_disconnect():
    sid = getattr(request, "sid", None)
    logger.info("[Socket.IO] disconnected sid=%s", sid)


def publish_thread_event(event_name: str, *, user_ids: list[Any], payload: dict[str, Any]) -> None:
    seen: set[str] = set()
    for raw_user_id in user_ids:
        user_uuid = _to_uuid(raw_user_id)
        if user_uuid is None:
            continue
        room = f"user:{user_uuid}"
        if room in seen:
            continue
        seen.add(room)
        socketio.emit(event_name, payload, room=room)
