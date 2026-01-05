# =====================================================================
# backend/dto/order_summary_dto.py
# ---------------------------------------------------------------------
# FILE ROLE:
#   Lightweight summary of an order.
#
# USED BY:
#   • User dashboards
#   • Farmer order lists
#   • Notifications and reporting
#
# PURPOSE:
#   Avoid exposing full Order ORM models to the frontend.
# =====================================================================

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class OrderSummaryDTO:
    """
    Condensed view of an order for listing and reporting.
    """

    order_id: UUID
    product_id: UUID
    buyer_id: UUID
    quantity: int
    status: str
    order_date: datetime
