# ====================================================================
# Redis-backed Circuit Breaker (SYNC)
# backend/utils/circuit_breaker.py
# ====================================================================
# PURPOSE / ROLE:
#   • Protects the backend from Redis instability.
#   • If Redis errors spike → breaker "opens" and cache is bypassed.
#   • Automatically resets after a cooldown window.
#
# WHY THIS FILE EXISTS:
#   • Redis outages can cause cascading failures (timeouts, request pile-ups).
#   • A circuit breaker keeps business logic running by bypassing cache when Redis is unhealthy.
#
# DESIGN:
#   • Uses Redis itself for shared breaker state across workers (gunicorn / uwsgi).
#   • Fail-safe behavior:
#       - If breaker state cannot be read, we treat it as OPEN (bypass cache).
#       - If breaker state cannot be written, we just continue (cache acts like miss).
#   • Pyright / Pylance clean:
#       - Redis client replies are defensively narrowed (ResponseT / Any handling).
# ====================================================================

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any, Optional, Union

import redis


# -----------------------------
# Helper parsing utilities
# -----------------------------
def _to_str(x: Any) -> Optional[str]:
    """
    Convert Redis reply to string safely.

    Redis replies may come back as:
      • str (decode_responses=True)
      • bytes (decode_responses=False)
      • int/float (some commands)
      • None
      • or generic "ResponseT" in type stubs

    Returns:
      str | None
    """
    if x is None:
        return None
    if isinstance(x, str):
        return x
    if isinstance(x, bytes):
        try:
            return x.decode("utf-8")
        except Exception:
            return None
    # Fallback: stringify unknown objects
    try:
        return str(x)
    except Exception:
        return None


def _to_float(x: Any) -> Optional[float]:
    """
    Convert Redis reply to float safely.
    """
    if x is None:
        return None
    if isinstance(x, (int, float)):
        return float(x)
    s = _to_str(x)
    if not s:
        return None
    try:
        return float(s)
    except Exception:
        return None


def _to_int(x: Any) -> Optional[int]:
    """
    Convert Redis reply to int safely.
    """
    if x is None:
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, float):
        return int(x)
    s = _to_str(x)
    if not s:
        return None
    try:
        return int(s)
    except Exception:
        return None


# ====================================================================
# Configuration
# ====================================================================
@dataclass(frozen=True)
class CircuitBreakerConfig:
    """
    Configuration for the Redis circuit breaker.

    failure_threshold:
      Number of failures within window_seconds that triggers "open".

    window_seconds:
      Rolling window for counting failures.

    open_seconds:
      How long breaker stays open before allowing attempts again.

    key_prefix:
      Namespace prefix for Redis keys.
    """
    failure_threshold: int = 10
    window_seconds: int = 60
    open_seconds: int = 30
    key_prefix: str = "agroconnect:cb:redis"


# ====================================================================
# Circuit Breaker
# ====================================================================
class RedisCircuitBreaker:
    """
    Redis-backed circuit breaker shared across backend workers.

    Use case:
      - Wrap cache calls:
          if breaker.is_open(): bypass cache
          else: try cache; on exception -> breaker.record_failure()
                               on success -> breaker.record_success()
    """

    def __init__(self, client: redis.Redis, config: Optional[CircuitBreakerConfig] = None) -> None:
        # NOTE: keep redis.Redis un-parameterized to avoid "Expected no type arguments" errors.
        self._client = client
        self._cfg = config or CircuitBreakerConfig()

        env = os.getenv("FLASK_ENV", "development") or "development"
        self._env = env.strip() or "development"

    # -----------------------------
    # Redis keys
    # -----------------------------
    def _key_failures(self) -> str:
        return f"{self._cfg.key_prefix}:{self._env}:failures"

    def _key_open_until(self) -> str:
        return f"{self._cfg.key_prefix}:{self._env}:open_until"

    # -----------------------------
    # Breaker state
    # -----------------------------
    def is_open(self) -> bool:
        """
        True when breaker is open and cache should be bypassed.

        Fail-safe:
          If Redis cannot be read, treat breaker as OPEN (bypass cache).
        """
        try:
            raw = self._client.get(self._key_open_until())
            open_until = _to_float(raw)
            if open_until is None:
                return False
            return time.time() < open_until
        except Exception:
            # Cannot read breaker state → bypass Redis for safety
            return True

    def record_success(self) -> None:
        """
        On a successful Redis operation:
          - Reset failures counter.
          - (Optional: could gradually decrement instead, but reset is simpler + safe.)
        """
        try:
            self._client.delete(self._key_failures())
        except Exception:
            return

    def record_failure(self) -> None:
        """
        Record a Redis error. If too many failures within the rolling window → open breaker.

        Implementation details:
          - failures counter uses INCR (atomic across workers)
          - counter expires after window_seconds (rolling window behavior)
          - open_until key is set with TTL open_seconds and value epoch timestamp
        """
        try:
            failures_key = self._key_failures()

            # INCR is atomic. Redis reply is usually int, but stubs may say ResponseT.
            raw_n = self._client.incr(failures_key)
            n = _to_int(raw_n) or 0

            # Ensure counter expires (rolling window).
            # Only set expiry when first created.
            if n == 1:
                self._client.expire(failures_key, int(self._cfg.window_seconds))

            if n >= int(self._cfg.failure_threshold):
                open_until_key = self._key_open_until()
                open_until = time.time() + float(self._cfg.open_seconds)

                # Store as string to keep it simple / portable.
                # TTL ensures automatic recovery after cooldown.
                self._client.setex(
                    open_until_key,
                    int(self._cfg.open_seconds),
                    str(open_until),
                )
        except Exception:
            return
