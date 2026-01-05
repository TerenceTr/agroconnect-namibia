# =====================================================================
# tests/test_recommender.py — Recommendation service caching tests
# =====================================================================
# ROLE:
#   • Verifies Redis-backed caching behavior in recommender service
#   • Ensures backend fetch is NOT repeated on cache hit
#
# IMPORTANT:
#   • We assert against the PATCHED mock, not module globals
#   • services.recommender is NOT a variable — it's a module path
# =====================================================================

from __future__ import annotations

import pytest

from ai_service.redis_cache import AsyncJsonCache
from ai_service.services import recommender
from ai_service.services.recommender import recommend_for_customer


@pytest.mark.asyncio
async def test_recommendation_cached(mocker, fake_redis):
    """
    Backend candidate fetch should be called only once
    when recommendations are cached.
    """

    # --------------------------------------------------
    # Arrange: wire FakeRedis cache into recommender
    # --------------------------------------------------
    cache = AsyncJsonCache(fake_redis)
    recommender.wire_cache(cache)

    # --------------------------------------------------
    # Patch backend fetch and CAPTURE the mock
    # --------------------------------------------------
    fetch_mock = mocker.patch(
        "ai_service.services.recommender._fetch_candidates",
        return_value={"items": []},
    )

    # --------------------------------------------------
    # Act: first call (cache miss)
    # --------------------------------------------------
    await recommend_for_customer(
        customer_id="1",
        query="maize",
        customer_lat=None,
        customer_lng=None,
        limit=5,
    )

    # --------------------------------------------------
    # Act: second call (cache hit)
    # --------------------------------------------------
    await recommend_for_customer(
        customer_id="1",
        query="maize",
        customer_lat=None,
        customer_lng=None,
        limit=5,
    )

    # --------------------------------------------------
    # Assert: backend fetch called only once
    # --------------------------------------------------
    assert fetch_mock.call_count == 1
