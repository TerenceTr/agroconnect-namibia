# ====================================================================
# ai_service/services/redis_client.py — Async Redis Client Factory
# ====================================================================
# FILE ROLE:
#   • Compatibility layer for older code paths
#   • Prefer using create_redis() from ai_service.services.redis_cache
#
# WHY THIS EXISTS:
#   Some modules may still import get_redis().
#   We keep it, but it must return a single consistent configuration.
# ====================================================================

from __future__ import annotations

from redis.asyncio import Redis

from ai_service.config import settings


def get_redis() -> Redis:
    """
    Create an async Redis client.

    NOTE:
      • For best practice, create ONE per worker and reuse.
      • In Phase 1, app.py should own the instance and pass it around.
    """
    return Redis.from_url(
        settings.redis_url,
        decode_responses=True,
    )
