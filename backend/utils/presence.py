# ====================================================================
# backend/utils/presence.py — Online User Tracking (Redis)
# ====================================================================
# PURPOSE:
#   • Track online / active users
#   • Shared by Socket.IO + REST APIs
#   • Redis-backed (horizontal scaling)
#
# PYLANCE FIXES:
#   • Redis values stored as str
#   • Protocol shim for hkeys typing
# ====================================================================

from __future__ import annotations

import time
from typing import Final, List, Protocol, cast

from backend.utils.socketio_rate_limit import redis as _redis

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


# ====================================================================
# Presence API
# ====================================================================
def mark_online(user_id: str) -> None:
    now = int(time.time())
    redis.hset(ONLINE_KEY, user_id, str(now))
    redis.expire(ONLINE_KEY, TTL_SECONDS)


def mark_active(user_id: str) -> None:
    mark_online(user_id)


def mark_offline(user_id: str) -> None:
    redis.hdel(ONLINE_KEY, user_id)


def list_online_users() -> List[str]:
    return list(redis.hkeys(ONLINE_KEY))


def presence_snapshot() -> dict[str, list[str] | int]:
    """
    Snapshot of presence state.

    online  → all connected users
    active  → users seen within TTL window
    """
    now = int(time.time())
    raw = redis.hgetall(ONLINE_KEY)

    online = list(raw.keys())
    active = [
        user_id
        for user_id, ts in raw.items()
        if now - int(ts) <= TTL_SECONDS
    ]

    return {
        "online": online,
        "active": active,
        "count": len(online),
    }
