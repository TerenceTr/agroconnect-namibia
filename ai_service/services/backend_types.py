# =====================================================================
# ai_service/services/backend_types.py — Backend API Contracts
# =====================================================================
# ROLE:
#   • Defines strict expected shapes of backend responses
#   • Prevents silent schema drift
#   • Makes backend_get() safe + predictable
# =====================================================================

from __future__ import annotations
from typing import TypedDict, List, Optional


class CandidateProduct(TypedDict):
    product_id: str
    product_name: str
    farmer_id: str
    farmer_name: str
    avg_rating: float
    total_orders: int
    farmer_lat: Optional[float]
    farmer_lng: Optional[float]


class CandidateResponse(TypedDict):
    items: List[CandidateProduct]
