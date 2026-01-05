# =====================================================================
# ai_service/services/circuit_breaker.py — Redis-backed Circuit Breaker
# =====================================================================
# FILE ROLE:
#   • Protects AI service operations and backend calls from cascading failures
#   • Uses Redis to share breaker state across workers and replicas
#   • Opens circuit when error rate exceeds threshold in a rolling window
#
# DESIGN PRINCIPLES:
#   • Async-safe (redis.asyncio)
#   • Fail-open (AI service never blocks if Redis is down)
#   • Per-operation isolation (name-based breakers)
#   • Deterministic and observable (MSc-grade)
# =====================================================================

from __future__ import annotations

import time
from dataclasses import dataclass

from redis.asyncio import Redis


# ---------------------------------------------------------------------
# Configuration (immutable)
# ---------------------------------------------------------------------
@dataclass(frozen=True)
class CircuitBreakerConfig:
    """
    Immutable configuration for circuit breaker behavior.
    """

    window_seconds: int = 60          # Rolling window size
    min_requests: int = 20            # Samples required before evaluation
    error_rate_threshold: float = 0.35
    cooldown_seconds: int = 60         # Open duration after tripping


# ---------------------------------------------------------------------
# Redis-backed Circuit Breaker
# ---------------------------------------------------------------------
class RedisCircuitBreaker:
    """
    Async Redis-backed circuit breaker.

    Breakers are keyed by logical operation name:
      • backend
      • rankings
      • recommendations
      • stock_alerts
    """

    def __init__(self, redis: Redis, cfg: CircuitBreakerConfig) -> None:
        self._redis = redis
        self._cfg = cfg

    # ---------------------------
    # Redis key helpers
    # ---------------------------
    def _k_total(self, name: str) -> str:
        return f"cb:v1:{name}:total"

    def _k_fail(self, name: str) -> str:
        return f"cb:v1:{name}:fail"

    def _k_open(self, name: str) -> str:
        return f"cb:v1:{name}:open_until"

    # ---------------------------
    # Public API
    # ---------------------------
    async def is_open(self, name: str) -> bool:
        """
        Return True if circuit is currently open.

        FAIL-OPEN:
          If Redis fails → allow traffic (never block AI).
        """
        try:
            raw = await self._redis.get(self._k_open(name))
            return raw is not None and float(raw) > time.time()
        except Exception:
            return False

    async def record_success(self, name: str) -> None:
        """Record a successful call."""
        await self._record(name, failed=False)

    async def record_failure(self, name: str) -> None:
        """Record a failed call."""
        await self._record(name, failed=True)

    # ---------------------------
    # Internal logic
    # ---------------------------
    async def _record(self, name: str, *, failed: bool) -> None:
        """
        Record one observation and trip circuit if needed.
        """
        try:
            pipe = self._redis.pipeline()

            pipe.incr(self._k_total(name))
            pipe.expire(self._k_total(name), self._cfg.window_seconds)

            if failed:
                pipe.incr(self._k_fail(name))
                pipe.expire(self._k_fail(name), self._cfg.window_seconds)

            await pipe.execute()

            total = int(await self._redis.get(self._k_total(name)) or 0)
            fails = int(await self._redis.get(self._k_fail(name)) or 0)

            if total < self._cfg.min_requests:
                return

            if (fails / total) >= self._cfg.error_rate_threshold:
                open_until = time.time() + self._cfg.cooldown_seconds
                await self._redis.setex(
                    self._k_open(name),
                    self._cfg.cooldown_seconds,
                    str(open_until),
                )
        except Exception:
            # Silent failure by design
            return

    # ---------------------------
    # Ops helpers
    # ---------------------------
    async def force_open(self, name: str) -> None:
        """Manually open circuit (ops/debug)."""
        try:
            until = time.time() + self._cfg.cooldown_seconds
            await self._redis.setex(self._k_open(name), self._cfg.cooldown_seconds, str(until))
        except Exception:
            return

    async def force_close(self, name: str) -> None:
        """Manually close circuit (ops/debug)."""
        try:
            await self._redis.delete(self._k_open(name))
        except Exception:
            return
