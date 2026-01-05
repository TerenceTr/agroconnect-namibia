# =====================================================================
# ai_service/config.py — AI Service Configuration
# =====================================================================
# FILE ROLE:
#   • Central configuration for the AI runtime (FastAPI microservice).
#   • Environment-driven settings:
#       - backend gateway URL + service token
#       - redis URL
#       - cache TTL
#       - model version metadata
#   • Keeps AI service DB-independent and reproducible.
# =====================================================================

from __future__ import annotations

import os
from dataclasses import dataclass


def _getenv(name: str, default: str) -> str:
    v = os.environ.get(name, default)
    return v.strip() if isinstance(v, str) else default


def _getint(name: str, default: str) -> int:
    raw = _getenv(name, default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _getbool(name: str, default: str) -> bool:
    return _getenv(name, default).lower() in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class Settings:
    # --------------------------------------------------
    # Runtime
    # --------------------------------------------------
    app_host: str = _getenv("APP_HOST", "0.0.0.0")
    app_port: int = _getint("APP_PORT", "8001")
    log_level: str = _getenv("LOG_LEVEL", "INFO")

    # --------------------------------------------------
    # Backend gateway
    # --------------------------------------------------
    backend_api_url: str = _getenv("BACKEND_API_URL", "http://localhost:5000")
    backend_service_token: str = _getenv("BACKEND_SERVICE_TOKEN", "")

    # --------------------------------------------------
    # Redis (cache + circuit breaker)
    # --------------------------------------------------
    redis_url: str = _getenv("REDIS_URL", "redis://localhost:6379/0")

    # Cache TTL (seconds)
    cache_ttl: int = _getint("AI_CACHE_TTL", "600")

    # --------------------------------------------------
    # Model rollout metadata
    # --------------------------------------------------
    model_version: str = _getenv("AI_MODEL_VERSION", "ai-v1.0.0")
    model_family: str = _getenv("AI_MODEL_FAMILY", "baseline")
    rollout_stage: str = _getenv("AI_ROLLOUT_STAGE", "stable")  # stable|canary|experimental

    # --------------------------------------------------
    # Client behavior
    # --------------------------------------------------
    fail_fast_enabled: bool = _getbool("AI_FAIL_FAST", "true")

    # --------------------------------------------------
    # Ranking defaults
    # --------------------------------------------------
    ranking_week_days: int = _getint("RANKING_WINDOW_WEEK", "7")
    ranking_month_days: int = _getint("RANKING_WINDOW_MONTH", "30")
    ranking_year_days: int = _getint("RANKING_WINDOW_YEAR", "365")


settings = Settings()
