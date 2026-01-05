# =====================================================================
# ai_service/schemas/requests.py — API Request Contracts (Pydantic v2)
# =====================================================================
# ROLE:
#   • Defines inbound request models (validated inputs only)
#   • This is the contract boundary for incoming requests
#   • No business logic, no persistence logic
# =====================================================================

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional
from typing_extensions import Annotated

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------
# PREDICTIONS
# ---------------------------------------------------------------------
class PredictionRequest(BaseModel):
    """
    Generic prediction input:
      - price prediction
      - demand prediction
      - baseline prediction
    """

    crop: Annotated[str, Field(min_length=2, description="Crop name")]
    data: Annotated[List[float], Field(min_length=1, description="Historical numeric series")]


# ---------------------------------------------------------------------
# FORECASTING
# ---------------------------------------------------------------------
class ForecastRequest(BaseModel):
    """
    Time-series forecasting input (ARIMA/fallback).
    """

    series: Annotated[List[float], Field(min_length=2, description="Time series values")]
    steps: Annotated[int, Field(ge=1, le=60, description="Forecast horizon")]=3


# ---------------------------------------------------------------------
# EVENTS (optional analytics capture)
# ---------------------------------------------------------------------
class SearchEvent(BaseModel):
    """
    Captures search behaviour for analysis / future personalization.
    """

    customer_id: str
    query: str
    customer_lat: Optional[float] = None
    customer_lng: Optional[float] = None
    ts_epoch: Optional[int] = None


# ---------------------------------------------------------------------
# RECOMMENDATIONS
# ---------------------------------------------------------------------
class RecommendationRequest(BaseModel):
    customer_id: str
    query: Optional[str] = None
    customer_lat: Optional[float] = None
    customer_lng: Optional[float] = None
    limit: Annotated[int, Field(ge=1, le=50)] = 10


# ---------------------------------------------------------------------
# RANKINGS
# ---------------------------------------------------------------------
class RankingRequest(BaseModel):
    window_days: Annotated[int, Field(ge=1, le=365)]
    top_n: Annotated[int, Field(ge=1, le=100)] = 10


# ---------------------------------------------------------------------
# STOCK ALERTS
# ---------------------------------------------------------------------
class StockAlertRequest(BaseModel):
    farmer_id: str
    threshold_days: Annotated[int, Field(ge=1, le=60)] = 7


# ---------------------------------------------------------------------
# ACCURACY LOGGING
# ---------------------------------------------------------------------
class AccuracyLogRequest(BaseModel):
    """
    Logs a prediction and optionally its ground truth (delayed supervision supported).
    """

    model_version: Annotated[str, Field(min_length=3)]
    task: Annotated[str, Field(pattern="^(price|demand|forecast)$")]
    crop: Annotated[str, Field(min_length=2)]

    entity_id: Optional[str] = None
    predicted_value: Annotated[float, Field(ge=0)]
    actual_value: Optional[Annotated[float, Field(ge=0)]] = None

    predicted_at: Optional[datetime] = None
    actual_at: Optional[datetime] = None

    meta: Optional[Dict[str, str]] = None


class AccuracyQueryRequest(BaseModel):
    """
    Query accuracy metrics over a time window.
    """

    task: Annotated[str, Field(pattern="^(price|demand|forecast)$")]
    model_version: Optional[str] = None
    crop: Optional[str] = None
    days: Annotated[int, Field(ge=1, le=365)] = 30
