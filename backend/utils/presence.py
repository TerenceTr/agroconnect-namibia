# ====================================================================
# backend/utils/presence.py — Online User Tracking (Redis, fail-open)
# ====================================================================
# PURPOSE:
#   • Track online / active users
#   • Shared by Socket.IO + REST APIs
#   • Redis-backed when available
#
# DEV/STABILITY UPDATE:
#   • Presence is now fail-open when Redis is unavailable.
#   • Socket.IO connect/disconnect must not crash just because local Redis is
#     down in development.
# ====================================================================

from __future__ import annotations

import logging
import time
from typing import Final, List, Protocol, cast

from backend.utils.socketio_rate_limit import redis as _redis

logger = logging.getLogger("backend.presence")


# --------------------------------------------------------------------
# Redis protocol shim
# --------------------------------------------------------------------
class RedisPresence(Protocol):
    def hset(self, name: str, key: str, value: str) -> int: ...
    def hdel(self, name: str, *keys: str) -> int: ...
    def hkeys(self, name: str) -> List[str]: ...
    def hgetall(self, name: str) -> dict[str, str]: ...
    def expire(self, name: str, time: int) -> bool: ...


redis: RedisPresence = cast(RedisPresence, _redis)

# --------------------------------------------------------------------
# Keys & TTL
# --------------------------------------------------------------------
ONLINE_KEY: Final[str] = "presence:online"
TTL_SECONDS: Final[int] = 60

# Warn once per process so dev logs stay readable.
_presence_backend_available = True


def _handle_presence_error(action: str, exc: Exception) -> None:
    global _presence_backend_available
    if _presence_backend_available:
        logger.warning(
            "Presence backend unavailable during %s; continuing without Redis-backed presence. Error: %s",
            action,
            exc,
        )
        _presence_backend_available = False


# ====================================================================
# Presence API
# ====================================================================
def mark_online(user_id: str) -> None:
    now = int(time.time())
    try:
        redis.hset(ONLINE_KEY, user_id, str(now))
        redis.expire(ONLINE_KEY, TTL_SECONDS)
    except Exception as exc:
        _handle_presence_error("mark_online", exc)


def mark_active(user_id: str) -> None:
    mark_online(user_id)


def mark_offline(user_id: str) -> None:
    try:
        redis.hdel(ONLINE_KEY, user_id)
    except Exception as exc:
        _handle_presence_error("mark_offline", exc)


def list_online_users() -> List[str]:
    try:
        return list(redis.hkeys(ONLINE_KEY))
    except Exception as exc:
        _handle_presence_error("list_online_users", exc)
        return []


def presence_snapshot() -> dict[str, list[str] | int]:
    """
    Snapshot of presence state.

    online  → all connected users
    active  → users seen within TTL window
    """
    now = int(time.time())

    try:
        raw = redis.hgetall(ONLINE_KEY)
    except Exception as exc:
        _handle_presence_error("presence_snapshot", exc)
        return {
            "online": [],
            "active": [],
            "count": 0,
        }

    online = list(raw.keys())
    active = []
    for user_id, ts in raw.items():
        try:
            if now - int(ts) <= TTL_SECONDS:
                active.append(user_id)
        except Exception:
            continue

    return {
        "online": online,
        "active": active,
        "count": len(online),
    }
