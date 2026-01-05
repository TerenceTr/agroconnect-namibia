# =====================================================================
# ai-service/schemas.py — API Contracts (Pydantic v2, PROD-GRADE)
# =====================================================================
# FILE ROLE:
#   • Defines ALL request/response schemas for the AI microservice.
#   • Stable contract boundary between backend ↔ ai-service ↔ frontend.
#   • No ORM objects or business logic may leak past this boundary.
# =====================================================================

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional
from typing_extensions import Annotated

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Used by monitoring, Docker health checks, and orchestration."""
    status: str
    service: str
    model_version: str


class PredictionRequest(BaseModel):
    """Generic prediction request used for baseline price/demand tasks."""
    crop: Annotated[str, Field(min_length=2, description="Crop name")]
    data: Annotated[List[float], Field(min_length=1, description="Historical numeric series")]


class ForecastRequest(BaseModel):
    """Time-series forecasting input (ARIMA / fallback models)."""
    series: Annotated[List[float], Field(min_length=2, description="Time series values")]
    steps: Annotated[int, Field(ge=1, le=60, description="Forecast horizon (days)")] = 3


class SearchEvent(BaseModel):
    """Captures customer search behaviour for pattern analysis."""
    customer_id: str
    query: str
    customer_lat: Optional[float] = None
    customer_lng: Optional[float] = None
    ts_epoch: Optional[int] = None


class RecommendationRequest(BaseModel):
    """Request for AI product recommendations."""
    customer_id: str
    customer_lat: Optional[float] = None
    customer_lng: Optional[float] = None
    limit: Annotated[int, Field(ge=1, le=50)] = 10


class RecommendationItem(BaseModel):
    """Single recommendation explanation unit."""
    product_id: str
    product_name: str
    farmer_id: str
    farmer_name: str
    distance_km: Optional[float] = None
    score: float
    reasons: List[str]


class RecommendationResponse(BaseModel):
    """Recommendation result set."""
    customer_id: str
    items: List[RecommendationItem]


class RankingRequest(BaseModel):
    """Ranking window selector."""
    window_days: Annotated[int, Field(ge=1, le=365)]
    top_n: Annotated[int, Field(ge=1, le=100)] = 10


class RankingItem(BaseModel):
    """Ranked entity (product or farmer)."""
    entity_id: str
    name: str
    score: float


class RankingResponse(BaseModel):
    """Ranking output for analytics dashboards."""
    window_days: int
    top_products: List[RankingItem]
    top_farmers: List[RankingItem]


class StockAlertRequest(BaseModel):
    """Request AI restock alerts for a farmer."""
    farmer_id: str
    threshold_days: Annotated[int, Field(ge=1, le=60)] = 7


class StockAlertItem(BaseModel):
    """AI-generated stock alert."""
    product_id: str
    product_name: str
    predicted_demand: float
    available_stock: float
    recommended_restock: float
    severity: Annotated[str, Field(pattern="^(low|medium|high)$")]


class StockAlertResponse(BaseModel):
    """Stock alert response payload."""
    farmer_id: str
    alerts: List[StockAlertItem]


class AccuracyLogRequest(BaseModel):
    """
    Logs a prediction and optional ground truth (supports delayed supervision).
    Enables offline accuracy computation / MSc evaluation.
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


class AccuracyLogResponse(BaseModel):
    """Response after logging an accuracy record."""
    status: str
    recorded: bool
    record_id: Optional[str] = None


class AccuracyQueryRequest(BaseModel):
    """Query stored accuracy metrics over a time window."""
    task: Annotated[str, Field(pattern="^(price|demand|forecast)$")]
    model_version: Optional[str] = None
    crop: Optional[str] = None
    days: Annotated[int, Field(ge=1, le=365)] = 30


class AccuracyMetrics(BaseModel):
    """Standard regression accuracy metrics."""
    n: int
    mae: float
    rmse: float
    mape: float


class AccuracyQueryResponse(BaseModel):
    """Accuracy evaluation response."""
    status: str
    task: str
    model_version: Optional[str] = None
    crop: Optional[str] = None
    window_days: int
    metrics: AccuracyMetrics
