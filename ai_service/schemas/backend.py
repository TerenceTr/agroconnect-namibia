# =====================================================================
# ai_service/schemas/backend.py — Backend Gateway DTOs
# =====================================================================
# FILE ROLE:
#   • Strongly typed request/response models for backend-provided data
#   • Prevents dictly-typed logic in service layer
#   • Centralizes backend contract assumptions (ranking inputs, stock inputs)
#
# DESIGN:
#   • Pydantic v2 compatible
#   • Defensive defaults and list factories
# =====================================================================

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------
# Ranking Inputs
# ---------------------------------------------------------------------
class ProductRankingInput(BaseModel):
    product_id: str
    product_name: str
    avg_rating: float = 0.0
    total_orders: int = 0


class FarmerRankingInput(BaseModel):
    farmer_id: str
    farmer_name: str
    avg_rating: float = 0.0
    fulfilled_orders: int = 0


class RankingInputsResponse(BaseModel):
    products: List[ProductRankingInput] = Field(default_factory=list)
    farmers: List[FarmerRankingInput] = Field(default_factory=list)


# ---------------------------------------------------------------------
# Stock Alert Inputs
# ---------------------------------------------------------------------
class StockInputItem(BaseModel):
    product_id: str
    product_name: str
    available_stock: float = 0.0
    recent_sales_series: List[float] = Field(default_factory=list)


class StockInputsResponse(BaseModel):
    items: List[StockInputItem] = Field(default_factory=list)
