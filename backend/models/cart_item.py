# ============================================================================
# backend/models/cart_item.py — CartItem Model (C1-ready, DB aligned)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Represents a user's cart line item (draft purchase).
#
# WHY THIS FILE IS UPDATED:
#   • Your DB uses products(product_id) not products(id)
#   • Your DB uses created_at as timestamptz (timezone=True)
#   • C1 needs decimal qty → Numeric(12,3) (requires migration if DB is integer)
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Optional, TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Numeric, UniqueConstraint, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from .product import Product
    from .user import User


class CartItem(db.Model):
    __tablename__ = "cart_items"

    # DB: cart_items.cart_item_id uuid PK
    id: Mapped[uuid.UUID] = mapped_column(
        "cart_item_id",
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # DB FK: cart_items.user_id -> users(id)
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # DB FK: cart_items.product_id -> products(product_id)
    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # C1: decimal quantities for kg/l/ml
    # NOTE: DB dump currently has qty INTEGER — apply migration below.
    qty: Mapped[Decimal] = mapped_column(
        Numeric(12, 3),
        nullable=False,
        default=Decimal("1.000"),
        server_default=text("1"),
    )

    # DB: created_at timestamp with time zone default now()
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Relationships (joined for cart UI rendering)
    user: Mapped["User"] = relationship("User", lazy="joined")
    product: Mapped[Optional["Product"]] = relationship("Product", lazy="joined")

    __table_args__ = (
        # DB: UNIQUE(user_id, product_id)
        UniqueConstraint("user_id", "product_id", name="cart_items_user_id_product_id_key"),
        # DB: qty > 0
        CheckConstraint("qty > 0", name="cart_items_qty_check"),
    )

    def to_dict(self) -> dict:
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "product_id": str(self.product_id),
            "qty": float(self.qty or 0),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
