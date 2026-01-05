# =====================================================================
# ai_service/services/base.py — Service Layer Shared Utilities
# =====================================================================
# FILE ROLE:
#   • Provides shared reliability + observability helpers for service modules
#   • Owns:
#       - retry decorator for async functions
#       - timed decorator for lightweight latency metrics
#       - shared service_logger
#
# RULES:
#   • NO FastAPI imports here
#   • Keep dependencies minimal and test-friendly
# =====================================================================

from __future__ import annotations

import asyncio
import functools
import time
import logging
from typing import Any, Awaitable, Callable, ParamSpec, TypeVar

from ai_service.services.metrics import inc

P = ParamSpec("P")
R = TypeVar("R")

service_logger = logging.getLogger("ai_service.services")
service_logger.addHandler(logging.NullHandler())


def timed(metric_name: str) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """
    Decorator to measure async function duration and store in in-memory counters.

    We keep it simple:
      • increments `timed.calls.<name>`
      • increments `timed.ms_total.<name>` (integer milliseconds)

    NOTE:
      This is intentionally not a histogram. You can later swap to Prometheus.
    """

    def decorator(func: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            inc(f"timed.calls.{metric_name}", 1)
            start = time.perf_counter()
            try:
                return await func(*args, **kwargs)
            finally:
                elapsed_ms = int((time.perf_counter() - start) * 1000)
                inc(f"timed.ms_total.{metric_name}", elapsed_ms)

        return wrapper

    return decorator


def retry(*, attempts: int = 3, delay_seconds: float = 0.25) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """
    Retry decorator for async functions.

    WHY:
      • Network calls (backend_get) may fail transiently.
      • Keeps retry logic consistent and testable.

    BEHAVIOR:
      • retries `attempts` times
      • sleeps delay_seconds between failures
      • re-raises last exception
    """

    def decorator(func: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        @functools.wraps(func)
        async def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
            last_exc: Exception | None = None
            for i in range(attempts):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001 (explicit by design)
                    last_exc = exc
                    if i == attempts - 1:
                        break
                    await asyncio.sleep(delay_seconds)
            assert last_exc is not None
            raise last_exc

        return wrapper

    return decorator
