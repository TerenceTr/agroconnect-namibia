# ====================================================================
# ai_service/services/cache_eviction.py — Model Version Cache Eviction
# ====================================================================
# FILE ROLE:
#   • Deletes cached AI outputs for a specific model_version
#   • Uses SCAN (safe) not KEYS (dangerous)
# ====================================================================

from __future__ import annotations

from ai_service.services.redis_cache import AsyncJsonCache


async def evict_model_version(cache: AsyncJsonCache, model_version: str) -> int:
    """
    Evict all cache entries for a given AI model version.

    Example key patterns:
      ai:ai-v1.0.0:price:<hash>
      ai:ai-v1.0.0:demand:<hash>
    """
    prefix = f"ai:{model_version}:"
    return await cache.delete_by_prefix(prefix)
