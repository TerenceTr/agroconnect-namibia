# =====================================================================
# ai_service/services/rankings.py — Product + Farmer Rankings
# =====================================================================
# FILE ROLE:
#   • Computes rankings using backend-provided aggregates
#   • Deterministic, explainable scoring
#   • Cache-first, breaker-safe
# =====================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ai_service.services.redis_cache import AsyncJsonCache
from ai_service.services.cache_decorators import async_cached
from ai_service.services._backend import backend_get
from ai_service.services.base import retry, service_logger, timed

_cache: Optional[AsyncJsonCache] = None


def wire_cache(cache: AsyncJsonCache) -> None:
    """Inject shared Redis cache instance (called from app.py)."""
    global _cache
    _cache = cache


def _rankings_cache_key(window_days: int, top_n: int) -> str:
    return f"ai:rankings:{window_days}:{top_n}"


def _score_product(p: Dict[str, Any]) -> float:
    return (float(p.get("avg_rating", 0.0)) * 2.0) + (float(p.get("total_orders", 0.0)) * 0.02)


def _score_farmer(f: Dict[str, Any]) -> float:
    return (float(f.get("avg_rating", 0.0)) * 2.5) + (float(f.get("fulfilled_orders", 0.0)) * 0.02)


@retry(attempts=3, delay_seconds=0.5)
@timed("rankings.fetch_inputs")
async def _fetch_inputs(window_days: int, top_n: int) -> Dict[str, Any]:
    return await backend_get(
        "/api/ai/ranking-inputs",
        params={"window_days": window_days, "top_n": top_n},
        breaker_name="rankings",
    )


@timed("rankings.compute_rankings")
async def compute_rankings(window_days: int, top_n: int) -> Dict[str, List[Dict[str, Any]]]:
    """
    Public API: cache-first compute rankings.

    NOTE:
      We wrap dynamically so we can use the injected cache instance.
    """
    if _cache is None:
        raise RuntimeError("Cache not wired (call wire_cache in app.py)")

    cached_fn = async_cached(
        cache=_cache,
        ttl_seconds=600,
        key_fn=_rankings_cache_key,
    )(_compute_rankings_impl)

    return await cached_fn(window_days, top_n)


async def _compute_rankings_impl(window_days: int, top_n: int) -> Dict[str, List[Dict[str, Any]]]:
    service_logger.info("compute_rankings(window_days=%d, top_n=%d)", window_days, top_n)

    data = await _fetch_inputs(window_days, top_n)

    products: List[Dict[str, Any]] = list(data.get("products") or data.get("top_products") or [])
    farmers: List[Dict[str, Any]] = list(data.get("farmers") or data.get("top_farmers") or [])

    for p in products:
        p["score"] = round(_score_product(p), 4)
    for f in farmers:
        f["score"] = round(_score_farmer(f), 4)

    products.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)
    farmers.sort(key=lambda x: float(x.get("score", 0.0)), reverse=True)

    return {"top_products": products[:top_n], "top_farmers": farmers[:top_n]}
