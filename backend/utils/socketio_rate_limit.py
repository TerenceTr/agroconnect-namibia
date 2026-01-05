# ====================================================================
# backend/utils/socketio_rate_limit.py — Redis Sliding Window Rate Limiter
# ====================================================================
# PURPOSE:
#   • Rate limit Socket.IO events (spam/abuse protection)
#   • Redis-backed so it works across multiple workers/processes
#
# PYLANCE FIX:
#   redis-py type stubs sometimes mark return types as ResponseT/Awaitable.
#   We use a small Protocol shim and cast the client to that Protocol.
# ====================================================================

from __future__ import annotations

import os
import time
from typing import Final, Optional, Protocol, cast

from redis import Redis

# --------------------------------------------------------------------
# Redis URL
# --------------------------------------------------------------------
REDIS_URL: Final[str] = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


# --------------------------------------------------------------------
# Minimal sync Redis protocol (fixes ResponseT/Awaitable typing noise)
# --------------------------------------------------------------------
class RedisSync(Protocol):
    def incr(self, name: str, amount: int = 1) -> int: ...
    def expire(self, name: str, time: int) -> bool: ...


# --------------------------------------------------------------------
# Create redis client and cast to our sync protocol
# --------------------------------------------------------------------
_redis = Redis.from_url(REDIS_URL, decode_responses=True)
redis: RedisSync = cast(RedisSync, _redis)

# --------------------------------------------------------------------
# Role-based default limits (events per window)
# --------------------------------------------------------------------
ROLE_LIMITS: Final[dict[str, int]] = {
    "admin": 200,
    "farmer": 60,
    "customer": 40,
    "anonymous": 20,
}


def allow_event(
    *,
    key: str,
    role: str,
    window: int,
    limit_override: Optional[int] = None,
) -> bool:
    """
    Sliding-window rate limiter.

    Args:
        key: unique identifier (e.g. "chat:<user_id>")
        role: "admin" | "farmer" | "customer" | "anonymous"
        window: window size in seconds
        limit_override: optional hard override

    Returns:
        True  -> allowed
        False -> blocked
    """
    limit: int = limit_override or ROLE_LIMITS.get(role, ROLE_LIMITS["anonymous"])

    now: int = int(time.time())
    bucket: int = now // window
    redis_key: str = f"rl:{key}:{bucket}"

    # Atomic increment (always int at runtime)
    count: int = redis.incr(redis_key)

    # TTL only on first hit in this bucket
    if count == 1:
        redis.expire(redis_key, window)

    return count <= limit
