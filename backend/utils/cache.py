# ====================================================================
# Redis Cache Helper (SYNC)
# backend/utils/cache.py
# ====================================================================
# ROLE:
#   • Centralized Redis cache access for Flask backend
#   • Safe JSON serialization/deserialization
#   • Hit/miss metrics + Redis circuit breaker protection
#
# DESIGN PRINCIPLES:
#   • Cache must NEVER crash business logic
#   • Redis instability must not cascade
#   • All Redis replies are treated as untrusted input
# ====================================================================

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Optional, cast

import redis

from backend.utils.circuit_breaker import RedisCircuitBreaker
from backend.utils.cache_keys import CacheKey


# --------------------------------------------------------------------
# Redis client (SYNC — Flask / WSGI)
# --------------------------------------------------------------------
redis_client = redis.Redis.from_url(
    os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    decode_responses=True,  # expect str, but still defend at runtime
)

# Shared circuit breaker instance
_breaker = RedisCircuitBreaker(redis_client)


# --------------------------------------------------------------------
# In-process cache metrics (per worker)
# --------------------------------------------------------------------
@dataclass
class CacheStats:
    hits: int = 0
    misses: int = 0
    sets: int = 0
    errors: int = 0


_stats = CacheStats()


def get_cache_stats() -> CacheStats:
    """Expose cache stats for health/debug endpoints."""
    return _stats


def reset_cache_stats() -> None:
    """Reset stats (useful for tests)."""
    _stats.hits = 0
    _stats.misses = 0
    _stats.sets = 0
    _stats.errors = 0


# --------------------------------------------------------------------
# Optional Redis-backed metrics (multi-worker aggregation)
# --------------------------------------------------------------------
def _metrics_incr(kind: str) -> None:
    """
    Increment cache metric counters in Redis.

    Safe-by-design:
      • Metrics must NEVER affect app correctness
    """
    try:
        if os.getenv("CACHE_METRICS_REDIS", "false").lower() != "true":
            return

        env = (os.getenv("FLASK_ENV", "development") or "development").strip()
        key = f"agroconnect:metrics:cache:{env}:{kind}"
        redis_client.incr(key)
        redis_client.expire(key, 60 * 60 * 24)  # 24h retention
    except Exception:
        return


# --------------------------------------------------------------------
# Key normalization
# --------------------------------------------------------------------
def _key_str(key: str | CacheKey) -> str:
    """Allow raw string keys or typed CacheKey objects."""
    return key.to_str() if isinstance(key, CacheKey) else key


# --------------------------------------------------------------------
# Cache: GET
# --------------------------------------------------------------------
def cache_get(key: str | CacheKey) -> Optional[Any]:
    """
    Retrieve JSON-serialized object from Redis.

    Behavior:
      • Breaker OPEN → bypass Redis
      • Redis error → record failure
      • Corrupt JSON → safe miss
    """
    k = _key_str(key)

    if _breaker.is_open():
        _stats.misses += 1
        _metrics_incr("miss")
        return None

    try:
        raw = redis_client.get(k)
    except Exception:
        _stats.errors += 1
        _metrics_incr("error")
        _breaker.record_failure()
        return None

    if raw is None:
        _stats.misses += 1
        _metrics_incr("miss")
        _breaker.record_success()
        return None

    # Defensive decode (even with decode_responses=True)
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except Exception:
            _stats.errors += 1
            _metrics_incr("error")
            _breaker.record_failure()
            return None

    raw_str = cast(str, raw)

    try:
        value = json.loads(raw_str)
    except json.JSONDecodeError:
        # Data corruption ≠ Redis failure
        _stats.errors += 1
        _metrics_incr("error")
        _breaker.record_success()
        return None

    _stats.hits += 1
    _metrics_incr("hit")
    _breaker.record_success()
    return value


# --------------------------------------------------------------------
# Cache: SET
# --------------------------------------------------------------------
def cache_set(key: str | CacheKey, value: Any, ttl: int) -> None:
    """
    Store JSON-serializable object in Redis.

    Behavior:
      • Breaker OPEN → no-op
      • Redis error → record failure, fail-silent
    """
    k = _key_str(key)
    ttl = int(ttl)

    if _breaker.is_open():
        return

    try:
        payload = json.dumps(value, default=str)
        redis_client.setex(k, ttl, payload)
        _stats.sets += 1
        _metrics_incr("set")
        _breaker.record_success()
    except Exception:
        _stats.errors += 1
        _metrics_incr("error")
        _breaker.record_failure()
        return
