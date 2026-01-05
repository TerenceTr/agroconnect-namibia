# ====================================================================
# backend/models/market_trend.py — Market Trend Snapshot (REL SAFE)
# ====================================================================
# FILE ROLE:
#   • Stores historical market trend snapshots per product
#   • Used by AI forecasting + analytics dashboards
#
# CRITICAL REQUIREMENT:
#   Product must define:
#     market_trends = relationship("MarketTrend", back_populates="product")
#   because this model uses:
#     product = relationship("Product", back_populates="market_trends")
# ====================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, Numeric
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.db import db

if TYPE_CHECKING:
    from .product import Product


def utc_now_naive() -> datetime:
    return datetime.utcnow()


class MarketTrend(db.Model):
    __tablename__ = "market_trends"

    trend_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    demand_index: Mapped[int] = mapped_column(Integer, nullable=False)
    avg_price: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)

    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        default=utc_now_naive,
        nullable=False,
        index=True,
    )

    product: Mapped["Product"] = relationship(
        "Product",
        back_populates="market_trends",
        lazy="joined",
        foreign_keys=[product_id],
        passive_deletes=True,
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trend_id": str(self.trend_id),
            "product_id": str(self.product_id),
            "demand_index": int(self.demand_index),
            "avg_price": float(self.avg_price),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
