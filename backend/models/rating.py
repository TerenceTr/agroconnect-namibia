# ====================================================================
# backend/models/rating.py — Product Rating (DB-DUMP ALIGNED)
# ====================================================================
# FILE ROLE:
#   • Stores user feedback for products (table: ratings)
#   • Used for admin/farmer overview (avg rating, latest reviews)
#
# WHY THIS FILE IS UPDATED:
#   • DB column name is rating_id, but Python attribute is commonly "id".
#   • Some routes/queries reference Rating.rating_id → Pyright complains.
#   • We keep the column mapped to "rating_id" and add a safe alias property.
#
# DB columns (from agroconnect_db.sql):
#   rating_id (uuid PK)
#   product_id (uuid FK -> products.product_id) ON DELETE CASCADE
#   user_id (uuid FK -> users.id) ON DELETE SET NULL   ✅ nullable
#   rating_score (int)
#   comments (text)
#   created_at (timestamp without tz, default now())
#   order_id (uuid nullable FK -> orders.order_id) ON DELETE SET NULL
# ====================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from .product import Product
    from .user import User
    from .order import Order


def utc_now_naive() -> datetime:
    return datetime.utcnow()


class Rating(db.Model):
    __tablename__ = "ratings"

    # DB: ratings.rating_id uuid PK
    id: Mapped[uuid.UUID] = mapped_column(
        "rating_id",
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # DB: ratings.product_id -> products.product_id
    product_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("products.product_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # DB: ratings.user_id nullable (ON DELETE SET NULL)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    rating_score: Mapped[int] = mapped_column(Integer, nullable=False)
    comments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # DB: timestamp without tz
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        default=utc_now_naive,
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    # DB: ratings.order_id nullable (ON DELETE SET NULL)
    order_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("orders.order_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Relationships
    # NOTE: Product must have back_populates="ratings" for this to work.
    product: Mapped["Product"] = relationship("Product", back_populates="ratings", lazy="selectin")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="ratings", lazy="selectin")
    order: Mapped[Optional["Order"]] = relationship("Order", lazy="selectin")

    # ----------------------------------------------------------------
    # Compatibility alias
    # ----------------------------------------------------------------
    @property
    def rating_id(self) -> uuid.UUID:
        """
        Alias for DB column naming.
        WHY:
          Some queries use Rating.rating_id; this keeps them valid without
          changing the underlying mapped attribute.
        """
        return self.id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "rating_id": str(self.id),  # explicit for API consumers
            "order_id": str(self.order_id) if self.order_id else None,
            "product_id": str(self.product_id),
            "user_id": str(self.user_id) if self.user_id else None,
            "rating_score": int(self.rating_score),
            "comments": self.comments,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
