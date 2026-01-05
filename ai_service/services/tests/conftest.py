# =====================================================================
# tests/conftest.py — Shared pytest fixtures
# =====================================================================
# ROLE:
#   • Provides a shared FakeRedis instance for async tests
#   • Used by cache tests, circuit breaker tests, and service tests
#
# IMPORTANT (typing):
#   • Async pytest fixtures using `yield` are ASYNC GENERATORS
#   • Therefore, the return type MUST be AsyncGenerator[…]
#   • NOT Redis directly
#
# This resolves:
#   ❌ "Return type of async generator function must be compatible with
#      AsyncGenerator[Any, Any]"
# =====================================================================

from __future__ import annotations

from typing import AsyncGenerator

import pytest
import fakeredis.aioredis
from redis.asyncio import Redis


@pytest.fixture
async def fake_redis() -> AsyncGenerator[Redis, None]:
    """
    Shared FakeRedis instance for async tests.

    WHY AsyncGenerator?
      • pytest async fixtures that use `yield` are async generators
      • Pyright/Pylance require correct generator typing

    LIFECYCLE:
      • Created once per test
      • Automatically cleaned up after test completes
    """
    redis: Redis = fakeredis.aioredis.FakeRedis(
        decode_responses=True
    )

    try:
        yield redis
    finally:
        # Ensure clean shutdown (matches production behavior)
        await redis.close()
