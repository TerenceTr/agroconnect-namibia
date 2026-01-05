# ====================================================================
# ai_service/services/redis_cache.py — Async Redis Cache Helper
# ====================================================================
# FILE ROLE:
#   • Creates the ONE shared Redis client (async pool) per worker.
#   • Provides AsyncJsonCache for safe JSON get/set with best-effort behavior.
#
# DESIGN:
#   • Uses redis.asyncio (official asyncio Redis client).
#   • Cache failures NEVER crash the AI service.
#   • Structural typing for cache keys via Protocol (as_redis_key()).
# ====================================================================

from __future__ import annotations

import json
import logging
from typing import Any, Optional, Protocol, Union, runtime_checkable

from redis.asyncio import Redis

from ai_service.config import settings

logger = logging.getLogger("ai_service.redis")
logger.addHandler(logging.NullHandler())


@runtime_checkable
class CacheKey(Protocol):
    """
    Structural type for typed cache keys.

    Any object implementing:
        as_redis_key() -> str
    is a valid cache key.
    """

    def as_redis_key(self) -> str: ...


class AsyncJsonCache:
    """
    Thin wrapper around async Redis with safe JSON encode/decode.

    WHY:
      • Keeps FastAPI handlers clean
      • Makes testing easier
      • Centralizes JSON handling + error swallowing
    """

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    def _key_to_str(self, key: str | CacheKey) -> str:
        return key if isinstance(key, str) else key.as_redis_key()

    async def get(self, key: str | CacheKey) -> Optional[Any]:
        k = self._key_to_str(key)
        try:
            raw: Optional[Union[str, bytes]] = await self._redis.get(k)
        except Exception:
            return None

        if raw is None:
            return None

        if isinstance(raw, bytes):
            try:
                raw = raw.decode("utf-8")
            except Exception:
                return None

        try:
            return json.loads(raw)
        except Exception:
            return None

    async def set(self, key: str | CacheKey, value: Any, ttl_seconds: int) -> None:
        k = self._key_to_str(key)
        try:
            payload = json.dumps(value, default=str, ensure_ascii=False)
            await self._redis.setex(k, int(ttl_seconds), payload)
        except Exception:
            return

    async def delete(self, key: str | CacheKey) -> bool:
        k = self._key_to_str(key)
        try:
            return bool(await self._redis.delete(k))
        except Exception:
            return False

    async def close(self) -> None:
        """
        Gracefully close Redis connection pool.
        Called from FastAPI lifespan shutdown.
        """
        try:
            await self._redis.close()
        except Exception:
            return


def create_redis() -> Redis:
    """
    Create the async Redis client.

    IMPORTANT:
      • This must be called ONCE per worker (app.py does this).
      • decode_responses=True gives str responses (better for JSON).
    """
    return Redis.from_url(settings.redis_url, decode_responses=True)


def create_cache(redis: Redis) -> AsyncJsonCache:
    """
    Create cache wrapper using the shared Redis client.
    """
    return AsyncJsonCache(redis)


__all__ = ["CacheKey", "AsyncJsonCache", "create_redis", "create_cache"]
