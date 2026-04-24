# ============================================================================
# backend/extensions.py — Flask Extensions Registry (PYRIGHT + RUNTIME-SAFE)
# ============================================================================
# FILE ROLE:
#   Owns extension singletons and centralizes init.
#
# KEY FIX:
#   Socket.IO should NOT attempt Redis unless REDIS_URL is explicitly set
#   AND reachable. This prevents "Cannot receive from redis..." spam in dev.
#
# DESIGN:
#   • bcrypt: supports flask-bcrypt (preferred) OR bcrypt (fallback)
#   • socketio: threading async_mode (Windows/dev-friendly)
# ============================================================================

from __future__ import annotations

import logging
import os
import socket
from typing import Any
from urllib.parse import urlparse

from flask import Flask
from flask_migrate import Migrate
from flask_socketio import SocketIO

logger = logging.getLogger("backend.extensions")

# --------------------------------------------------------------------
# Preferred: flask-bcrypt (optional dependency)
# --------------------------------------------------------------------
try:
    from flask_bcrypt import Bcrypt as _FlaskBcrypt  # type: ignore
except Exception:  # pragma: no cover
    _FlaskBcrypt = None  # type: ignore[assignment]

# --------------------------------------------------------------------
# Fallback: bcrypt package (optional dependency)
# --------------------------------------------------------------------
try:
    import bcrypt as _bcrypt  # type: ignore
except Exception:  # pragma: no cover
    _bcrypt = None  # type: ignore[assignment]


class SafeBcrypt:
    """Minimal, stable bcrypt wrapper (works with flask-bcrypt or bcrypt)."""

    def __init__(self) -> None:
        self._impl: Any = _FlaskBcrypt() if _FlaskBcrypt else None

    def init_app(self, app: Flask) -> None:
        if self._impl is not None:
            self._impl.init_app(app)

    def generate_password_hash(self, password: str) -> bytes:
        if not isinstance(password, str):
            password = str(password)

        # Preferred path
        if self._impl is not None:
            out = self._impl.generate_password_hash(password)
            if isinstance(out, (bytes, bytearray)):
                return bytes(out)
            if isinstance(out, str):
                return out.encode("utf-8")
            raise RuntimeError("flask-bcrypt returned unexpected hash type")

        # Fallback path
        if _bcrypt is None:
            raise RuntimeError("Install 'flask-bcrypt' or 'bcrypt' for password hashing.")

        salt = _bcrypt.gensalt()
        return _bcrypt.hashpw(password.encode("utf-8"), salt)

    def check_password_hash(self, pw_hash: Any, password: str) -> bool:
        if pw_hash is None:
            return False
        if not isinstance(password, str):
            password = str(password)

        # Preferred path
        if self._impl is not None:
            try:
                return bool(self._impl.check_password_hash(pw_hash, password))
            except Exception:
                return False

        # Fallback path
        if _bcrypt is None:
            return False

        if isinstance(pw_hash, str):
            hash_bytes = pw_hash.encode("utf-8")
        elif isinstance(pw_hash, (bytes, bytearray)):
            hash_bytes = bytes(pw_hash)
        else:
            return False

        try:
            return bool(_bcrypt.checkpw(password.encode("utf-8"), hash_bytes))
        except Exception:
            return False


bcrypt = SafeBcrypt()
migrate = Migrate()

# Windows/dev-friendly default (no eventlet/gevent required)
socketio = SocketIO(async_mode="threading")


def _redis_reachable(redis_url: str, timeout: float = 0.25) -> bool:
    """
    Lightweight reachability check (no redis-py dependency).
    If host:port can't be reached, don't enable message_queue.
    """
    try:
        u = urlparse(redis_url)
        host = u.hostname or "localhost"
        port = u.port or 6379
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def init_socketio(app: Flask, *, cors_allowed_origins: Any = "*") -> None:
    """
    Initialize Socket.IO.
    Only enables Redis message queue if REDIS_URL is set AND reachable.
    """
    redis_url = (os.getenv("REDIS_URL") or "").strip() or None

    reachable = bool(redis_url) and _redis_reachable(redis_url) if redis_url else False

    if redis_url and reachable:
        logger.info("✅ Socket.IO using Redis queue: %s", redis_url)
        socketio.init_app(app, cors_allowed_origins=cors_allowed_origins, message_queue=redis_url)
        return

    if redis_url and not reachable:
        logger.warning("⚠️ REDIS_URL is set but Redis is not reachable. Starting without Redis queue.")

    socketio.init_app(app, cors_allowed_origins=cors_allowed_origins)
