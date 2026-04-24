# ============================================================================
# backend/models/order.py — Order Model (DB-safe + Option A Compatible)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Order header model matching the real DB columns from agroconnect_db.sql.
#
# DB ALIGNMENT (CONFIRMED IN agroconnect_db.sql):
#   - order_id                 UUID PRIMARY KEY DEFAULT uuid_generate_v4()
#   - buyer_id                 UUID NOT NULL (FK → users.id)
#   - order_date               TIMESTAMP NOT NULL DEFAULT now()
#   - status                   VARCHAR(50) NOT NULL DEFAULT 'pending'
#   - order_total              NUMERIC(10,2) DEFAULT 0
#   - delivery_method          VARCHAR(20) DEFAULT 'delivery'
#   - delivery_address         TEXT NULL
#   - delivery_status          VARCHAR(20) DEFAULT 'pending'
#   - expected_delivery_date   TIMESTAMP NULL
#   - delivered_at             TIMESTAMP NULL
#   - delivery_fee             NUMERIC(12,2) NOT NULL DEFAULT 0
#   - delivery_fee_status      TEXT NULL
#   - delivery_fee_suggested   NUMERIC(12,2) NULL
#   - delivery_distance_km     NUMERIC(12,2) NULL
#
# IMPORTANT:
#   ✅ Payment fields are NOT in orders table (they are in payments table),
#      so we DO NOT declare payment_status/payment_method/paid_at here.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import date, datetime, time
from decimal import Decimal
from typing import Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym
from sqlalchemy.types import TypeDecorator

from backend.database.db import db

if TYPE_CHECKING:
    from backend.models.order_item import OrderItem
    from backend.models.user import User


class FlexibleDateTime(TypeDecorator):
    """
    Accepts datetime/date/ISO-string inputs and stores a TIMESTAMP.
    Helpful because some routes send YYYY-MM-DD (date) for expected_delivery_date.
    """
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, date):
            return datetime.combine(value, time.min)
        if isinstance(value, str):
            s = value.strip()
            if not s:
                return None
            if s.endswith("Z"):
                s = s[:-1]
            try:
                # date-only
                if len(s) == 10 and s[4] == "-" and s[7] == "-":
                    d = date.fromisoformat(s)
                    return datetime.combine(d, time.min)
                return datetime.fromisoformat(s)
            except Exception:
                return None
        return value


class Order(db.Model):  # type: ignore[misc]
    __tablename__ = "orders"

    # ---------------------------------------------------------------------
    # Primary Key (DB = UUID)
    # ---------------------------------------------------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        "order_id",
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("public.uuid_generate_v4()"),
    )
    order_id = synonym("id")

    # ---------------------------------------------------------------------
    # Buyer
    # ---------------------------------------------------------------------
    buyer_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=False,
        index=True,
    )

    # ---------------------------------------------------------------------
    # Timestamps / status
    # ---------------------------------------------------------------------
    order_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
    )
    created_at = synonym("order_date")

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        server_default=text("'pending'"),
        index=True,
    )

    # ---------------------------------------------------------------------
    # Totals
    # ---------------------------------------------------------------------
    order_total: Mapped[Optional[Decimal]] = mapped_column(
        Numeric(10, 2),
        nullable=True,
        server_default=text("0"),
    )
    total = synonym("order_total")

    # ---------------------------------------------------------------------
    # Delivery fields (DB confirmed)
    # ---------------------------------------------------------------------
    delivery_method: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
        server_default=text("'delivery'"),
    )

    delivery_address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    delivery_status: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True,
        server_default=text("'pending'"),
        index=True,
    )

    expected_delivery_date: Mapped[Optional[datetime]] = mapped_column(
        FlexibleDateTime(timezone=False),
        nullable=True,
    )

    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)

    delivery_fee: Mapped[Decimal] = mapped_column(
        Numeric(12, 2),
        nullable=False,
        server_default=text("0"),
    )

    delivery_fee_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    delivery_fee_suggested: Mapped[Optional[Decimal]] = mapped_column(Numeric(12, 2), nullable=True)

    delivery_distance_km: Mapped[Optional[Decimal]] = mapped_column(Numeric(12, 2), nullable=True)

    # ---------------------------------------------------------------------
    # Relationships
    # ---------------------------------------------------------------------
    buyer: Mapped["User"] = relationship("User", foreign_keys=[buyer_id])

    items: Mapped[list["OrderItem"]] = relationship(
        "OrderItem",
        back_populates="order",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<Order id={self.id} buyer_id={self.buyer_id} status={self.status}>"

# DB has indexes idx_orders_status, idx_orders_delivery_status (keep ORM hints)
Index("idx_orders_status", Order.status)
Index("idx_orders_delivery_status", Order.delivery_status)
