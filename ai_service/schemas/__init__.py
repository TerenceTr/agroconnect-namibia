# =====================================================================
# ai_service/schemas/__init__.py — Schema Exports
# =====================================================================
# FILE ROLE:
#   • Defines the public surface for schemas (Pydantic models)
#   • Allows stable imports:
#       from ai_service.schemas import PredictionRequest, RankingResponse, ...
#
# IMPORTANT:
#   • This module should remain stable even if internal structure changes
#   • All external imports flow through ai_service.schemas.api
# =====================================================================

from __future__ import annotations

from ai_service.schemas.api import (  # noqa: F401
    AccuracyLogRequest,
    AccuracyLogResponse,
    AccuracyMetrics,
    AccuracyQueryRequest,
    AccuracyQueryResponse,
    ForecastRequest,
    HealthResponse,
    PredictionRequest,
    RankingItem,
    RankingRequest,
    RankingResponse,
    RecommendationItem,
    RecommendationRequest,
    RecommendationResponse,
    SearchEvent,
    StockAlertItem,
    StockAlertRequest,
    StockAlertResponse,
)

__all__ = [
    "HealthResponse",
    "PredictionRequest",
    "ForecastRequest",
    "SearchEvent",
    "RecommendationRequest",
    "RecommendationItem",
    "RecommendationResponse",
    "RankingRequest",
    "RankingItem",
    "RankingResponse",
    "StockAlertRequest",
    "StockAlertItem",
    "StockAlertResponse",
    "AccuracyLogRequest",
    "AccuracyLogResponse",
    "AccuracyQueryRequest",
    "AccuracyQueryResponse",
    "AccuracyMetrics",
]
