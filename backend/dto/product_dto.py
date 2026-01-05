# =====================================================================
# backend/dto/product_dto.py
# ---------------------------------------------------------------------
# FILE ROLE:
#   Canonical, immutable product data contract.
#
# USED BY:
#   • API responses
#   • AI recommendation pipelines
#   • Ranking and search systems
#
# ARCHITECTURE VALUE:
#   ✔ Decouples persistence layer from consumers
#   ✔ Stabilizes API contracts
#   ✔ MSc-level layered design
# =====================================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from uuid import UUID


@dataclass(frozen=True, slots=True)
class ProductDTO:
    """
    Read-only product representation.

    This DTO may include aggregated metrics that do NOT exist
    on the Product database table.
    """

    id: UUID
    name: str
    category: Optional[str]
    price: float
    location: Optional[str]
    farmer_id: UUID

    # Derived / aggregated metrics
    average_rating: Optional[float] = None
    total_sales: Optional[int] = None
