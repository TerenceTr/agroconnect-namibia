# ============================================================================
# backend/models/order_item.py — OrderItem Model (C1 + Multi-item Orders)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   One purchased line item within an Order (orders + order_items schema).
#
# KEY FIXES:
#   • FK targets match DB column names:
#       - orders PK is orders.order_id (not orders.id)
#       - products PK is products.product_id (not products.id)
#   • Align numeric precision with DB
#   • Snapshot unit/pack fields for C1 analytics and historical correctness
#   • back_populates wired to Product.order_items for mapper stability
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from .order import Order
    from .product import Product


class OrderItem(db.Model):
    __tablename__ = "order_items"

    # DB: order_items.order_item_id uuid PK
    id: Mapped[uuid.UUID] = mapped_column(
        "order_item_id",
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # DB: FK -> orders(order_id)
    order_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("orders.order_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # DB: FK -> products(product_id)
    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("products.product_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # DB: numeric(12,3), numeric(10,2), numeric(12,2)
    quantity: Mapped[Decimal] = mapped_column(Numeric(12, 3), nullable=False)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    line_total: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)

    # C1 snapshot fields
    unit: Mapped[str] = mapped_column(String(20), nullable=False)
    pack_size: Mapped[Optional[Decimal]] = mapped_column(Numeric(12, 3), nullable=True)
    pack_unit: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    # DB: timestamp WITHOUT time zone default now()
    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=False),
        nullable=True,
        server_default=func.now(),
    )

    # Relationships
    order: Mapped["Order"] = relationship("Order", back_populates="items")
    product: Mapped["Product"] = relationship("Product", back_populates="order_items", lazy="joined")

    __table_args__ = (
        Index("ix_order_items_order_id", "order_id"),
        Index("ix_order_items_product_id", "product_id"),
    )

    def to_dict(self) -> dict:
        p = getattr(self, "product", None)
        product_name = None
        if p is not None:
            product_name = getattr(p, "product_name", None) or getattr(p, "name", None)

        return {
            "id": str(self.id),
            "order_id": str(self.order_id),
            "product_id": str(self.product_id),
            "product_name": product_name,
            "quantity": float(self.quantity or 0),
            "unit": self.unit,
            "pack_size": float(self.pack_size) if self.pack_size is not None else None,
            "pack_unit": self.pack_unit,
            "unit_price": float(self.unit_price or 0),
            "line_total": float(self.line_total or 0),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
