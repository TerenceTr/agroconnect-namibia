# =====================================================================
# backend/dto/farmer_stats_dto.py
# ---------------------------------------------------------------------
# FILE ROLE:
#   Immutable data-transfer object representing aggregated farmer stats.
#
# USED BY:
#   • Analytics endpoints
#   • Admin dashboards
#   • Ranking / recommendation engines
#
# DESIGN PRINCIPLES:
#   ✔ Read-only (frozen dataclass)
#   ✔ No ORM / SQLAlchemy dependency
#   ✔ Safe to serialize and cache
# =====================================================================

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class FarmerStatsDTO:
    """
    Aggregated statistics for a farmer.

    This DTO is derived from multiple tables (orders, ratings)
    and should NEVER be written back to the database.
    """

    farmer_id: UUID
    farmer_name: str
    avg_rating: float
    fulfilled_orders: int
