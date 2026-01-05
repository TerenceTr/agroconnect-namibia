# ====================================================================
# backend/models/ai_stock_alert.py — AI Stock Alert Entity (DB-SCHEMA MATCH)
# ====================================================================
# FILE ROLE:
#   • Persists AI-generated stock risk alerts (demand vs stock)
#   • Supports acknowledgement + resolution workflow
#
# IMPORTANT:
#   This version matches your actual DB schema in agroconnect_db.sql:
#     • computed_date
#     • acknowledged / acknowledged_at
#     • resolved / resolved_at
# ====================================================================

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone
from typing import Any, Dict, TYPE_CHECKING

from sqlalchemy import Boolean, Date, DateTime, Float, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.db import db

if TYPE_CHECKING:
    from .user import User
    from .product import Product


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AIStockAlert(db.Model):
    __tablename__ = "ai_stock_alerts"

    # ---------------- Identity ----------------
    alert_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ---------------- Foreign Keys ----------------
    farmer_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ---------------- AI Metrics ----------------
    predicted_demand: Mapped[float] = mapped_column(Float, nullable=False)
    available_stock: Mapped[float] = mapped_column(Float, nullable=False)
    recommended_restock: Mapped[float] = mapped_column(Float, nullable=False)

    severity: Mapped[str] = mapped_column(Text, nullable=False)       # low|medium|high
    model_version: Mapped[str] = mapped_column(Text, nullable=False)

    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        nullable=False,
        index=True,
    )

    # NOTE: In your DB this exists (often generated/derived from computed_at)
    computed_date: Mapped[date | None] = mapped_column(Date, nullable=True, index=True)

    # ---------------- Workflow ----------------
    acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    resolved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # ---------------- Relationships ----------------
    farmer: Mapped["User"] = relationship(
        "User",
        back_populates="ai_stock_alerts",
        lazy="joined",
        foreign_keys=[farmer_id],
    )

    product: Mapped["Product"] = relationship(
        "Product",
        back_populates="ai_stock_alerts",
        lazy="joined",
        foreign_keys=[product_id],
    )

    # ---------------- Serialization ----------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": str(self.alert_id),
            "farmer_id": str(self.farmer_id),
            "product_id": str(self.product_id),
            "predicted_demand": float(self.predicted_demand),
            "available_stock": float(self.available_stock),
            "recommended_restock": float(self.recommended_restock),
            "severity": str(self.severity),
            "model_version": str(self.model_version),
            "computed_at": self.computed_at.isoformat() if self.computed_at else None,
            "computed_date": self.computed_date.isoformat() if self.computed_date else None,
            "acknowledged": bool(self.acknowledged),
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "resolved": bool(self.resolved),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }
