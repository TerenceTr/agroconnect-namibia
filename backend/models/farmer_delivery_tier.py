# ============================================================================
# backend/models/farmer_delivery_tier.py — Farmer Delivery Pricing Tier
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores farmer-configurable delivery pricing rules (distance tiers).
#
#   Example tier:
#     0–5km     → free
#     6–10km    → N$30
#     11–15km   → N$60
#     100km+    → N$200 + weight fee
#
# THIS VERSION FIXES:
#   ✅ Uses SQLAlchemy `Uuid` directly instead of `db.Uuid`
#   ✅ Uses SQLAlchemy `text(...)` directly instead of `db.text(...)`
#   ✅ Uses SQLAlchemy `func.now()` directly instead of `db.func.now()`
#   ✅ Keeps SQLAlchemy 2.x typed ORM style
# ============================================================================

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, Numeric, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db


class FarmerDeliveryTier(db.Model):
    __tablename__ = "farmer_delivery_tiers"

    # ------------------------------------------------------------------------
    # Primary key
    # ------------------------------------------------------------------------
    # Use SQLAlchemy's UUID type directly for Pyright compatibility.
    id: Mapped[UUID] = mapped_column(
        Uuid,
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )

    # ------------------------------------------------------------------------
    # Owner / farmer reference
    # ------------------------------------------------------------------------
    farmer_id: Mapped[UUID] = mapped_column(
        Uuid,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    # ------------------------------------------------------------------------
    # Distance band definition
    # ------------------------------------------------------------------------
    km_min: Mapped[int] = mapped_column(Integer, nullable=False)
    km_max: Mapped[int] = mapped_column(Integer, nullable=False)

    # ------------------------------------------------------------------------
    # Pricing structure
    # ------------------------------------------------------------------------
    # base_fee:
    #   The fixed delivery charge for this band.
    #
    # included_kg:
    #   How many kilograms are included before extra per-kg fees apply.
    #
    # per_kg_fee:
    #   Additional fee charged per kg beyond the included amount.
    base_fee: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
    )
    included_kg: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
    )
    per_kg_fee: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        default=Decimal("0"),
    )

    # ------------------------------------------------------------------------
    # Tier flags
    # ------------------------------------------------------------------------
    is_free: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ------------------------------------------------------------------------
    # Audit timestamps
    # ------------------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )