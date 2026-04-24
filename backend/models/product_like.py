# ============================================================================
# backend/models/product_like.py — Product Like Model (mapper-safe + API-safe)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores "customer likes product" interactions for preference/ranking features.
#
# WHY THIS VERSION:
#   ✅ FK targets are DB-aligned for your schema:
#      - users.id
#      - products.product_id
#   ✅ Adds typed relationships (user, product) so expressions like
#      ProductLike.product are recognized by type-checkers (Pyright/Pylance).
#   ✅ Includes to_dict() used by likes routes.
#   ✅ Keeps model mapper-safe (no back_populates dependency required).
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from backend.database.db import db

if TYPE_CHECKING:
    from .product import Product
    from .user import User


def _dt_iso(value: Optional[datetime]) -> Optional[str]:
    """Serialize datetime safely for JSON payloads."""
    return value.isoformat() if isinstance(value, datetime) else None


class ProductLike(db.Model):  # type: ignore[misc]
    __tablename__ = "product_likes"

    # ---------------------------------------------------------------------
    # Primary key
    # ---------------------------------------------------------------------
    like_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        # If uuid-ossp is enabled in Postgres, DB can also generate this.
        server_default=text("public.uuid_generate_v4()"),
    )

    # Compatibility alias (older code may use .id)
    id = synonym("like_id")

    # ---------------------------------------------------------------------
    # Foreign keys (DB-aligned)
    # ---------------------------------------------------------------------
    user_id: Mapped[uuid.UUID] = mapped_column(
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

    # ---------------------------------------------------------------------
    # Timestamp
    # ---------------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # ---------------------------------------------------------------------
    # Relationships (typed for Pyright/Pylance)
    # ---------------------------------------------------------------------
    # NOTE:
    #   No back_populates required — this keeps startup resilient even if
    #   User/Product models don't define reciprocal relationships.
    user: Mapped["User"] = relationship("User", lazy="joined")
    product: Mapped["Product"] = relationship("Product", lazy="joined")

    # One user can like a product only once.
    __table_args__ = (
        UniqueConstraint("user_id", "product_id", name="uq_product_likes_user_product"),
    )

    # ---------------------------------------------------------------------
    # Serialization helper
    # ---------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """
        Route-safe serializer.
        Includes lightweight product metadata if relationship is available.
        """
        p = getattr(self, "product", None)

        product_name = None
        image_url = None
        category = None
        if p is not None:
            product_name = getattr(p, "product_name", None) or getattr(p, "name", None)
            image_url = getattr(p, "image_url", None)
            category = getattr(p, "category", None)

        return {
            "like_id": str(self.like_id),
            "id": str(self.like_id),  # compatibility
            "user_id": str(self.user_id),
            "product_id": str(self.product_id),
            "created_at": _dt_iso(self.created_at),
            "product_name": product_name,
            "image_url": image_url,
            "category": category,
        }
