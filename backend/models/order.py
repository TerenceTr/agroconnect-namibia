# ============================================================================
# backend/models/order.py — Order Model (Multi-item + C1 totals)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Purchase "header" row:
#     • buyer/status/payment metadata
#     • contains many OrderItems (order_items table)
#
# KEY FIX:
#   • buyer relationship MUST use back_populates="orders"
#     because User.orders uses back_populates="buyer".
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Dict, List, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.db import db

if TYPE_CHECKING:
    from .order_item import OrderItem
    from .user import User


class Order(db.Model):
    __tablename__ = "orders"

    # DB: orders.order_id uuid PK
    id: Mapped[uuid.UUID] = mapped_column(
        "order_id",
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # DB: orders.buyer_id references users(id)
    buyer_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
        index=True,
    )

    payment_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unpaid",
        server_default=text("'unpaid'"),
        index=True,
    )

    # DB: timestamp WITHOUT time zone
    order_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
        index=True,
    )

    paid_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=False),
        nullable=True,
    )

    payment_reference: Mapped[Optional[str]] = mapped_column(
        String(120),
        nullable=True,
    )

    order_total: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=Decimal("0.00"),
        server_default=text("0"),
    )

    # ---------------------------------------------------------------------
    # Relationships
    # ---------------------------------------------------------------------

    buyer: Mapped["User"] = relationship(
    "User",
    back_populates="orders",     # ✅ matches User.orders back_populates="buyer"
    foreign_keys=[buyer_id],
    lazy="joined",
    )

    items: Mapped[List["OrderItem"]] = relationship(
        "OrderItem",
        back_populates="order",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_orders_buyer_id", "buyer_id"),
        Index("ix_orders_order_date", "order_date"),
    )

    # Compatibility aliases
    @property
    def order_id(self) -> str:
        return str(self.id)

    @property
    def total(self) -> float:
        return float(self.order_total or 0)

    @staticmethod
    def _iso(dt: Optional[datetime]) -> Optional[str]:
        return dt.isoformat() if dt else None

    def to_dict(self, *, include_items: bool = True) -> Dict[str, object]:
        items_list = list(self.items or []) if include_items else []

        item_count = len(items_list)
        first_item_name = None
        if item_count >= 1:
            first_item_name = getattr(items_list[0], "to_dict", lambda: {})().get("product_name")

        data: Dict[str, object] = {
            "id": str(self.id),
            "order_id": str(self.id),
            "buyer_id": str(self.buyer_id),

            "buyer_name": getattr(self.buyer, "full_name", None),

            "status": self.status,
            "payment_status": self.payment_status,
            "payment_reference": self.payment_reference,

            "order_date": self._iso(self.order_date),
            "paid_at": self._iso(self.paid_at),

            "order_total": float(self.order_total or 0),
            "total": self.total,

            "item_count": item_count,
            "items_preview": first_item_name if item_count <= 1 else f"{first_item_name} +{item_count - 1} more",
        }

        if include_items:
            data["items"] = [it.to_dict() for it in items_list]

        return data
