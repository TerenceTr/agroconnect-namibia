# =====================================================================
# ai_service/services/cache_decorators.py — Async Cache Decorators
# =====================================================================
# FILE ROLE:
#   • Declarative Redis-backed caching for async services
#   • Emits cache hit/miss metrics
#   • Best-effort: failures never break execution
# =====================================================================

from __future__ import annotations

from functools import wraps
from typing import Any, Awaitable, Callable, TypeVar

from ai_service.services.redis_cache import AsyncJsonCache
from ai_service.services.metrics import inc

R = TypeVar("R")


def async_cached(
    *,
    cache: AsyncJsonCache,
    ttl_seconds: int,
    key_fn: Callable[..., str],
) -> Callable[[Callable[..., Awaitable[R]]], Callable[..., Awaitable[R]]]:
    """
    Decorate an async function with Redis-backed caching.

    Notes:
      • Result must be JSON-serializable
      • Cache failures are swallowed safely
    """

    def decorator(func: Callable[..., Awaitable[R]]) -> Callable[..., Awaitable[R]]:
        @wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> R:
            key = key_fn(*args, **kwargs)

            cached = await cache.get(key)
            if cached is not None:
                inc("cache.hit", 1)
                return cached  # type: ignore[return-value]

            inc("cache.miss", 1)
            result = await func(*args, **kwargs)
            await cache.set(key, result, ttl_seconds)
            return result

        return wrapper

    return decorator
