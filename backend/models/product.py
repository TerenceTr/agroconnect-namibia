# ============================================================================
# backend/models/product.py — Product Model (MAPPER-SAFE + PYLANCE-FRIENDLY)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Core Product ORM model (table: products).
#
# KEY FIXES:
#   1) Provide Product.to_dict()
#   2) Provide QUERY-SAFE aliases using synonym(): id/name/stock
#   3) Include unit/pack fields for C1 unit system
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Numeric, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from .user import User
    from .rating import Rating
    from .ai_stock_alert import AIStockAlert
    from .market_trend import MarketTrend
    from .order_item import OrderItem


class Product(db.Model):  # type: ignore[misc]
    """
    Product listing created/owned by a farmer.

    Notes:
      • Decimal-safe quantities (Numeric) support fractional units (C1 approach).
      • Keeps compatibility aliases (id/name/stock) usable in queries.
    """

    __tablename__ = "products"

    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    farmer_id: Mapped[uuid.UUID] = mapped_column(
        "user_id",
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    product_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    price: Mapped[Decimal] = mapped_column(
        Numeric(10, 2),
        nullable=False,
        default=Decimal("0.00"),
    )

    quantity: Mapped[Decimal] = mapped_column(
        Numeric(12, 3),
        nullable=False,
        default=Decimal("0"),
    )

    status: Mapped[str] = mapped_column(String(50), nullable=False, server_default="available", index=True)
    image_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Unit system (C1)
    unit: Mapped[str] = mapped_column(String(20), nullable=False, server_default="each")
    pack_size: Mapped[Optional[Decimal]] = mapped_column(Numeric(12, 3), nullable=True)
    pack_unit: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        server_default=func.now(),
        nullable=False,
    )

    # Compatibility aliases (QUERY-SAFE)
    id = synonym("product_id")
    name = synonym("product_name")
    stock = synonym("quantity")

    # Relationships
    farmer: Mapped["User"] = relationship(
        "User",
        back_populates="products",
        foreign_keys=[farmer_id],
        passive_deletes=True,
    )

    ratings: Mapped[list["Rating"]] = relationship(
        "Rating",
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    ai_stock_alerts: Mapped[list["AIStockAlert"]] = relationship(
        "AIStockAlert",
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    market_trends: Mapped[list["MarketTrend"]] = relationship(
        "MarketTrend",
        back_populates="product",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    order_items: Mapped[list["OrderItem"]] = relationship(
    "OrderItem",
    back_populates="product",    # ✅ mirrors OrderItem.product back_populates="order_items"
    lazy="select",
    passive_deletes=True,
    )

    def to_dict(self) -> dict[str, Any]:
        farmer = getattr(self, "farmer", None)
        farmer_name = getattr(farmer, "full_name", None) if farmer is not None else None

        return {
            "id": str(self.product_id),
            "product_id": str(self.product_id),
            "farmer_id": str(self.farmer_id),
            "name": self.product_name,
            "product_name": self.product_name,
            "description": self.description,
            "category": self.category,
            "price": float(self.price or 0),
            "quantity": float(self.quantity or 0),
            "stock": float(self.quantity or 0),
            "status": self.status,
            "image_url": self.image_url,
            "unit": self.unit,
            "pack_size": float(self.pack_size) if self.pack_size is not None else None,
            "pack_unit": self.pack_unit,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "farmer_name": farmer_name,
        }


Index("ix_products_farmer_name", Product.farmer_id, Product.product_name)
