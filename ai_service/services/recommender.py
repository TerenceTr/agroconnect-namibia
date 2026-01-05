# =====================================================================
# ai_service/services/recommender.py — Personalized Recommendations
# =====================================================================
# FILE ROLE:
#   • Produces explainable customer-specific recommendations
#   • Penalizes distance to promote local sourcing
#
# DESIGN:
#   • Pure service module (NO FastAPI)
#   • Cache injected from app.py
# =====================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ai_service.services.redis_cache import AsyncJsonCache
from ai_service.services.cache_decorators import async_cached
from ai_service.services.distance import haversine_km
from ai_service.services._backend import backend_get
from ai_service.services.base import service_logger, timed, retry

_cache: Optional[AsyncJsonCache] = None


def wire_cache(cache: AsyncJsonCache) -> None:
    """Inject shared Redis cache instance (called from app.py)."""
    global _cache
    _cache = cache


@retry(attempts=3, delay_seconds=0.5)
@timed("recommender.fetch_candidates")
async def _fetch_candidates(*, customer_id: str, query: str, limit: int) -> Dict[str, Any]:
    return await backend_get(
        "/api/ai/candidates",
        params={"customer_id": customer_id, "q": query, "limit": limit},
        breaker_name="recommendations",
    )


def _recommendation_cache_key(
    *,
    customer_id: str,
    query: Optional[str],
    customer_lat: Optional[float],
    customer_lng: Optional[float],
    limit: int,
) -> str:
    return f"ai:recommendations:{customer_id}:{query or ''}:{customer_lat}:{customer_lng}:{limit}"


@timed("recommender.recommend_for_customer")
async def recommend_for_customer(
    *,
    customer_id: str,
    query: Optional[str],
    customer_lat: Optional[float],
    customer_lng: Optional[float],
    limit: int,
) -> List[Dict[str, Any]]:
    """
    Explainable linear scoring model:
      score = rating*2 + popularity*0.02 - distance_penalty
    """
    if _cache is None:
        raise RuntimeError("Cache not wired (call wire_cache in app.py)")

    cached_fn = async_cached(
        cache=_cache,
        ttl_seconds=300,
        key_fn=_recommendation_cache_key,
    )(_recommend_for_customer_impl)

    return await cached_fn(
        customer_id=customer_id,
        query=query,
        customer_lat=customer_lat,
        customer_lng=customer_lng,
        limit=limit,
    )


async def _recommend_for_customer_impl(
    *,
    customer_id: str,
    query: Optional[str],
    customer_lat: Optional[float],
    customer_lng: Optional[float],
    limit: int,
) -> List[Dict[str, Any]]:
    q = (query or "").strip()
    service_logger.info("recommend_for_customer(customer_id=%s, q=%r, limit=%d)", customer_id, q, limit)

    payload = await _fetch_candidates(customer_id=customer_id, query=q, limit=limit * 3)

    items = payload.get("items", [])
    if not isinstance(items, list):
        return []

    results: List[Dict[str, Any]] = []
    for c in items:
        rating = float(c.get("avg_rating", 0.0))
        popularity = float(c.get("total_orders", 0.0))

        dist = haversine_km(
            customer_lat,
            customer_lng,
            c.get("farmer_lat"),
            c.get("farmer_lng"),
        )

        # Penalty saturates at 2.0 (so distance never dominates quality)
        penalty = 0.0 if dist is None else min(dist / 50.0, 2.0)
        score = (rating * 2.0) + (popularity * 0.02) - penalty

        results.append(
            {
                "product_id": str(c.get("product_id", "")),
                "product_name": str(c.get("product_name", "")),
                "farmer_id": str(c.get("farmer_id", "")),
                "farmer_name": str(c.get("farmer_name", "")),
                "distance_km": dist,
                "score": round(score, 4),
                "reasons": [
                    f"rating={round(rating,2)}",
                    f"orders={int(popularity)}",
                    ("local_distance" if dist is not None and dist < 50 else "distance_unknown_or_far"),
                ],
            }
        )

    results.sort(key=lambda x: float(x["score"]), reverse=True)
    return results[:limit]
