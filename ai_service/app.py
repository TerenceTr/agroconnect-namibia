# =====================================================================
# ai_service/app.py — FastAPI AI Microservice
# =====================================================================
# FILE ROLE:
#   • Entry point for AgroConnect AI microservice
#   • Wires Redis, cache, and circuit breaker ONCE per worker
#   • Exposes health + metrics endpoints
# =====================================================================

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Dict

from dotenv import load_dotenv
from fastapi import FastAPI

from ai_service.config import settings
from ai_service.schemas import HealthResponse
from ai_service.services.redis_cache import create_redis, create_cache
from ai_service.services.circuit_breaker import CircuitBreakerConfig, RedisCircuitBreaker
from ai_service.services.metrics import snapshot
from ai_service.services._backend import wire_backend_breaker

# ---------------------------------------------------------------------
# Environment & logging
# ---------------------------------------------------------------------
load_dotenv()

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO)
)
logger = logging.getLogger("ai_service")

# ---------------------------------------------------------------------
# Shared infrastructure (ONE per worker)
# ---------------------------------------------------------------------
redis = create_redis()
cache = create_cache(redis)

breaker_cfg = CircuitBreakerConfig()
breaker = RedisCircuitBreaker(redis, breaker_cfg)

# ---------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_: FastAPI):
    # Inject breaker into backend HTTP client
    wire_backend_breaker(breaker)

    logger.info("[ai_service] startup complete")
    yield
    await cache.close()
    logger.info("[ai_service] shutdown complete")


app = FastAPI(
    title="AgroConnect AI Service",
    version=settings.model_version,
    lifespan=lifespan,
)

# ---------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="ai_service",
        model_version=settings.model_version,
    )


@app.get("/health/circuit")
async def health_circuit() -> Dict[str, Any]:
    return {
        "breaker": {
            "backend": await breaker.is_open("backend"),
            "rankings": await breaker.is_open("rankings"),
            "recommendations": await breaker.is_open("recommendations"),
            "stock_alerts": await breaker.is_open("stock_alerts"),
        }
    }


@app.get("/metrics")
async def metrics() -> Dict[str, Any]:
    return {
        "counters": snapshot(),
        "breaker": {
            "backend": await breaker.is_open("backend"),
        },
    }
