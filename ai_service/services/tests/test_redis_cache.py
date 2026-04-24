# ====================================================================
# ai_service/tests/test_redis_cache.py — AsyncJsonCache unit tests
# ====================================================================
# ROLE:
#   • Verifies correctness of AsyncJsonCache behavior
#   • Uses fakeredis (async) — no real Redis required
#
# DESIGN GUARANTEES:
#   • Cache failures never crash service
#   • Corrupt JSON is ignored safely
#   • Keys support structural typing (as_redis_key)
# ====================================================================

from __future__ import annotations

import pytest
import fakeredis.aioredis

from ai_service.services.redis_cache import AsyncJsonCache


# --------------------------------------------------------------------
# Typed cache key used for testing (STRUCTURAL typing)
# --------------------------------------------------------------------
class TestKey:
    """
    Minimal typed cache key for tests.

    Implements:
        as_redis_key() -> str
    """

    def __init__(self, value: str) -> None:
        self.value = value

    def as_redis_key(self) -> str:
        return f"test:{self.value}"


# --------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------
@pytest.fixture
def cache() -> AsyncJsonCache:
    """
    Fresh AsyncJsonCache backed by FakeRedis per test.
    """
    redis = fakeredis.aioredis.FakeRedis(decode_responses=True)
    return AsyncJsonCache(redis)


# --------------------------------------------------------------------
# Tests
# --------------------------------------------------------------------
@pytest.mark.asyncio
async def test_cache_get_missing_returns_none(cache: AsyncJsonCache) -> None:
    """
    Cache miss should return None.
    """
    key = TestKey("missing")
    value = await cache.get(key)
    assert value is None


@pytest.mark.asyncio
async def test_cache_set_and_get_roundtrip(cache: AsyncJsonCache) -> None:
    """
    Stored JSON-serializable value must round-trip correctly.
    """
    key = TestKey("roundtrip")
    payload = {"a": 1, "b": [1, 2, 3]}

    await cache.set(key, payload, ttl_seconds=60)
    value = await cache.get(key)

    assert value == payload


@pytest.mark.asyncio
async def test_cache_handles_corrupt_json(cache: AsyncJsonCache) -> None:
    """
    Corrupt JSON in Redis must be ignored safely.
    """
    key = TestKey("corrupt")

    # Write invalid JSON directly into Redis
    await cache._redis.set(key.as_redis_key(), "{bad-json")

    value = await cache.get(key)
    assert value is None


@pytest.mark.asyncio
async def test_cache_delete_removes_key(cache: AsyncJsonCache) -> None:
    """
    Delete must remove the key and return False on subsequent get.
    """
    key = TestKey("delete")
    await cache.set(key, {"x": 1}, ttl_seconds=60)

    assert await cache.get(key) == {"x": 1}

    deleted = await cache.delete(key)
    assert deleted is True

    assert await cache.get(key) is None


@pytest.mark.asyncio
async def test_cache_is_best_effort_on_redis_failure(mocker) -> None:
    """
    Redis failures must NOT crash the cache.
    """
    fake_redis = mocker.AsyncMock()
    fake_redis.get.side_effect = RuntimeError("Redis down")

    cache = AsyncJsonCache(fake_redis)

    # Should not raise
    value = await cache.get("any-key")
    assert value is None

    # set() should also not raise
    await cache.set("any-key", {"x": 1}, ttl_seconds=10)
