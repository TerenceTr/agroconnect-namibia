# =====================================================================
# ai_service/services/redis_cache.py — Async Redis Cache Helper
# =====================================================================
# FILE ROLE:
#   • Provides async Redis cache abstraction for AI services
#   • Centralizes:
#       - Redis client creation (SINGLE pool per worker)
#       - JSON serialization / deserialization
#       - Safe cache lifecycle management
#
# DESIGN:
#   • redis.asyncio (official client)
#   • Structural typing for cache keys (Protocol-based)
#   • Cache failures NEVER crash the service
# =====================================================================

from __future__ import annotations

import json
from typing import Any, Optional, Protocol, Union, runtime_checkable

from redis.asyncio import Redis

from ai_service.config import settings


@runtime_checkable
class CacheKey(Protocol):
    """Structural cache key contract (anything with as_redis_key())."""

    def as_redis_key(self) -> str: ...


def create_redis() -> Redis:
    """
    Create async Redis client.

    IMPORTANT:
      Create ONE per worker and reuse it for:
        • AsyncJsonCache
        • RedisCircuitBreaker
    """
    return Redis.from_url(
        settings.redis_url,
        decode_responses=True,  # Redis returns str instead of bytes
    )


class AsyncJsonCache:
    """Thin async Redis wrapper with safe JSON handling."""

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

    async def delete_by_prefix(
        self,
        prefix: str,
        *,
        batch_size: int = 500,
        max_keys: int = 50_000,
    ) -> int:
        """
        Safely delete keys by prefix using SCAN (NOT KEYS).

        NOTE:
          `unlink` is preferred (non-blocking), fallback to delete.
        """
        deleted = 0
        cursor = 0
        seen = 0

        try:
            while True:
                cursor, keys = await self._redis.scan(
                    cursor=cursor,
                    match=f"{prefix}*",
                    count=batch_size,
                )

                if keys:
                    seen += len(keys)
                    if seen > max_keys:
                        break
                    try:
                        await self._redis.unlink(*keys)
                    except Exception:
                        await self._redis.delete(*keys)
                    deleted += len(keys)

                if cursor == 0:
                    break
        except Exception:
            return deleted

        return deleted

    async def close(self) -> None:
        """Close Redis connection pool."""
        try:
            await self._redis.close()
        except Exception:
            return


def create_cache(redis: Redis) -> AsyncJsonCache:
    """Create AsyncJsonCache from an existing Redis client."""
    return AsyncJsonCache(redis)


__all__ = ["CacheKey", "AsyncJsonCache", "create_redis", "create_cache"]
