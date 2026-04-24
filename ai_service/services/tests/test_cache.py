# =====================================================================
# tests/test_cache.py — AsyncJsonCache unit tests
# =====================================================================

from __future__ import annotations

import pytest
import fakeredis.aioredis

from ai_service.services.redis_cache import AsyncJsonCache


# --------------------------------------------------------------------
# Typed cache key used for testing
# --------------------------------------------------------------------
class RankingsKey:
    def __init__(self, *, window_days: int, top_n: int) -> None:
        self.window_days = window_days
        self.top_n = top_n

    def as_redis_key(self) -> str:
        return f"ai:rankings:{self.window_days}:{self.top_n}"


# --------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cache_set_get_roundtrip() -> None:
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cache = AsyncJsonCache(r)

    key = RankingsKey(window_days=7, top_n=10)
    value = {"items": [1, 2, 3], "meta": {"ok": True}}

    await cache.set(key, value, ttl_seconds=60)
    assert await cache.get(key) == value


@pytest.mark.asyncio
async def test_cache_get_missing_returns_none() -> None:
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cache = AsyncJsonCache(r)

    key = RankingsKey(window_days=30, top_n=5)
    assert await cache.get(key) is None


@pytest.mark.asyncio
async def test_cache_get_corrupted_json_returns_none() -> None:
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cache = AsyncJsonCache(r)

    key = RankingsKey(window_days=1, top_n=10)
    await r.set(key.as_redis_key(), "{not-json}")

    assert await cache.get(key) is None


@pytest.mark.asyncio
async def test_cache_delete_removes_key() -> None:
    r = fakeredis.aioredis.FakeRedis(decode_responses=True)
    cache = AsyncJsonCache(r)

    key = RankingsKey(window_days=7, top_n=3)
    await cache.set(key, {"x": 1}, ttl_seconds=60)

    assert await cache.get(key) == {"x": 1}
    await cache.delete(key)
    assert await cache.get(key) is None
