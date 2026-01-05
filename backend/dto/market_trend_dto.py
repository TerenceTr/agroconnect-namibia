# =====================================================================
# backend/dto/market_trend_dto.py
# ---------------------------------------------------------------------
# FILE ROLE:
#   Read-only representation of AI-generated market trends.
#
# USED BY:
#   • AI forecasting services
#   • Analytics APIs
#   • Historical trend visualizations
#
# NOTES:
#   - This data is typically derived from ML models
#   - Not tied to a specific ORM table
# =====================================================================

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class MarketTrendDTO:
    """
    Snapshot of a computed market trend for a product.
    """

    product_id: UUID
    demand_index: float
    avg_price: float
    model_version: str
    timestamp: datetime
