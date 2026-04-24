# ============================================================================
# backend/models/order_item.py — OrderItem Model (C1 + Item Delivery) [DB-ALIGNED]
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Represents a single purchased line inside an Order (table: order_items).
#   Used by:
#     • Checkout (creating line items)
#     • Farmer Orders page (shows per-item info + partial delivery updates)
#
# DB ALIGNMENT (agroconnect_db.sql):
#   - order_item_id      UUID PRIMARY KEY DEFAULT uuid_generate_v4()
#   - order_id           UUID NOT NULL  (FK → orders.order_id)
#   - product_id         UUID NOT NULL  (FK → products.product_id)
#   - quantity           NUMERIC(12,3) NOT NULL
#   - unit_price         NUMERIC(10,2) NOT NULL
#   - line_total         NUMERIC(12,2) NOT NULL
#   - unit               VARCHAR(20) NOT NULL
#   - fulfillment_status VARCHAR(20) NOT NULL DEFAULT 'pending'
#   - delivery_status    VARCHAR(20) NOT NULL DEFAULT 'pending'
#   - delivered_quantity NUMERIC(12,3) NULL
#   - created_at         TIMESTAMP NOT NULL DEFAULT now()
#
# IMPORTANT:
#   DB column is `delivered_quantity`, but app code frequently uses
#   `delivered_qty`, so we map delivered_qty -> delivered_quantity.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Numeric, String, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from backend.database.db import db

if TYPE_CHECKING:
    from .order import Order
    from .product import Product


# -----------------------------------------------------------------------------
# Local helpers
# -----------------------------------------------------------------------------
def _dt_iso(v: Any) -> Optional[str]:
    return v.isoformat() if isinstance(v, datetime) else None


def _d(v: Any) -> Decimal:
    try:
        if v is None:
            return Decimal("0")
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except Exception:
        return Decimal("0")


class OrderItem(db.Model):  # type: ignore[misc]
    __tablename__ = "order_items"

    # ---------------------------------------------------------------------
    # Primary Key (UUID)
    # ---------------------------------------------------------------------
    order_item_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("public.uuid_generate_v4()"),
    )

    # Compatibility aliases
    id = synonym("order_item_id")
    item_id = synonym("order_item_id")

    # ---------------------------------------------------------------------
    # Foreign Keys (DB aligned)
    # ---------------------------------------------------------------------
    order_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("orders.order_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("products.product_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # ---------------------------------------------------------------------
    # Quantities & pricing
    # ---------------------------------------------------------------------
    quantity: Mapped[Decimal] = mapped_column(Numeric(12, 3), nullable=False)
    unit_price: Mapped[Decimal] = mapped_column(Numeric(10, 2), nullable=False)
    line_total: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)

    # Snapshot unit (required by DB)
    unit: Mapped[str] = mapped_column(String(20), nullable=False)

    # ---------------------------------------------------------------------
    # Fulfillment / delivery
    # ---------------------------------------------------------------------
    fulfillment_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default=text("'pending'"),
    )

    delivery_status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        server_default=text("'pending'"),
    )

    # DB column name = delivered_quantity
    delivered_qty: Mapped[Optional[Decimal]] = mapped_column(
        "delivered_quantity",
        Numeric(12, 3),
        nullable=True,
    )

    # Compatibility aliases used across routes/UI
    delivered_quantity = synonym("delivered_qty")
    item_delivery_status = synonym("delivery_status")

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        server_default=text("now()"),
    )

    # ---------------------------------------------------------------------
    # Relationships
    # ---------------------------------------------------------------------
    order: Mapped["Order"] = relationship("Order", back_populates="items")
    product: Mapped["Product"] = relationship("Product", lazy="joined")

    # ---------------------------------------------------------------------
    # Serialization helper
    # ---------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        p = getattr(self, "product", None)

        product_name = None
        image_url = None
        category = None
        if p is not None:
            product_name = getattr(p, "product_name", None) or getattr(p, "name", None)
            image_url = getattr(p, "image_url", None)
            category = getattr(p, "category", None)

        dq = self.delivered_qty
        quantity = _d(self.quantity)

        return {
            "order_item_id": str(self.order_item_id),
            "order_id": str(self.order_id),
            "product_id": str(self.product_id),

            "product_name": product_name,
            "image_url": image_url,
            "category": category,

            "quantity": float(quantity),
            "unit": self.unit,
            "unit_price": float(_d(self.unit_price)),
            "line_total": float(_d(self.line_total)),

            "fulfillment_status": self.fulfillment_status,
            "delivery_status": self.delivery_status,

            # keep both keys for compatibility
            "delivered_qty": float(_d(dq)) if dq is not None else 0.0,
            "delivered_quantity": float(_d(dq)) if dq is not None else 0.0,

            "created_at": _dt_iso(self.created_at),
        }
