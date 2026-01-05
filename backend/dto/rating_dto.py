# =====================================================================
# backend/dto/rating_dto.py
# ---------------------------------------------------------------------
# FILE ROLE:
#   Immutable representation of a product rating.
#
# USED BY:
#   • Reviews API
#   • Aggregation services
#   • Recommendation scoring
# =====================================================================

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RatingDTO:
    """
    Read-only rating event.
    """

    product_id: UUID
    user_id: UUID
    rating_score: int
    created_at: datetime
