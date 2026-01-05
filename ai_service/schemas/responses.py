# =====================================================================
# ai_service/schemas/responses.py — API Response Contracts (Pydantic v2)
# =====================================================================
# ROLE:
#   • Defines outbound schemas for API responses
#   • Ensures stable OpenAPI contracts and frontend expectations
# =====================================================================

from __future__ import annotations

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------
# HEALTH
# ---------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str
    service: str
    model_version: str
    schema_version: str


# ---------------------------------------------------------------------
# RECOMMENDATIONS
# ---------------------------------------------------------------------
class RecommendationItem(BaseModel):
    product_id: str
    product_name: str
    farmer_id: str
    farmer_name: str
    distance_km: Optional[float] = None
    score: float
    reasons: List[str]


class RecommendationResponse(BaseModel):
    customer_id: str
    items: List[RecommendationItem]


# ---------------------------------------------------------------------
# RANKINGS
# ---------------------------------------------------------------------
class RankingItem(BaseModel):
    entity_id: str
    name: str
    score: float


class RankingResponse(BaseModel):
    window_days: int
    top_products: List[RankingItem]
    top_farmers: List[RankingItem]


# ---------------------------------------------------------------------
# STOCK ALERTS
# ---------------------------------------------------------------------
class StockAlertItem(BaseModel):
    product_id: str
    product_name: str
    predicted_demand: float
    available_stock: float
    recommended_restock: float
    severity: str = Field(pattern="^(low|medium|high)$")


class StockAlertResponse(BaseModel):
    farmer_id: str
    alerts: List[StockAlertItem]


# ---------------------------------------------------------------------
# ACCURACY
# ---------------------------------------------------------------------
class AccuracyMetrics(BaseModel):
    n: int
    mae: float
    rmse: float
    mape: float


class AccuracyLogResponse(BaseModel):
    status: str
    recorded: bool
    record_id: Optional[str] = None


class AccuracyQueryResponse(BaseModel):
    status: str
    task: str
    model_version: Optional[str] = None
    crop: Optional[str] = None
    window_days: int
    metrics: AccuracyMetrics
