# ====================================================================
# Lightweight Metrics Logger (Redis-backed)
# ====================================================================

from __future__ import annotations
import time
import redis
import os

r = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))

def record_metric(name: str, value: float = 1.0) -> None:
    r.incrbyfloat(f"metrics:{name}", value)

def record_latency(name: str, start: float) -> None:
    elapsed = time.time() - start
    r.incrbyfloat(f"metrics:{name}:latency", elapsed)
