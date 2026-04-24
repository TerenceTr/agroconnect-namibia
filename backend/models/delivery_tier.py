# ============================================================================
# DeliveryTier model — Distance-based delivery pricing
# ============================================================================
# FILE ROLE:
#   Stores farmer-defined delivery fee tiers based on distance (km).
#   Used during cart preview + checkout.
# ============================================================================

from sqlalchemy import Numeric, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from backend.database.db import db


class DeliveryTier(db.Model):
    __tablename__ = "delivery_tiers"

    tier_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    farmer_id: Mapped[UUID] = mapped_column(UUID(as_uuid=True), nullable=False)

    min_km: Mapped[float] = mapped_column(Numeric, nullable=False)
    max_km: Mapped[float] = mapped_column(Numeric, nullable=False)
    fee: Mapped[float] = mapped_column(Numeric, nullable=False)

    created_at: Mapped[DateTime] = mapped_column(
        DateTime, server_default=func.now()
    )
