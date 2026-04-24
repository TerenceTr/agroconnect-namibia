# ============================================================================
# backend/models/user.py — User Model (DB-ALIGNED + MAPPER-SAFE + PYLANCE-FRIENDLY)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Core user entity mapped to `public.users`.
#   Provides role constants + helpers used across auth, dashboards, and policies.
#
# IMPORTANT FIX IN THIS VERSION:
#   ✅ Disambiguates User ↔ Rating relationships now that Rating has:
#        - user_id       -> review author
#        - moderated_by  -> admin moderator
#   ✅ Adds explicit foreign_keys so SQLAlchemy mapper configuration is stable
#   ✅ Adds moderated_ratings relationship for admin governance history
# ============================================================================

from __future__ import annotations

import importlib.util
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db

# ---------------------------------------------------------------------------
# Type-check-only imports (avoid runtime circular imports)
# ---------------------------------------------------------------------------
if TYPE_CHECKING:
    from .ai_stock_alert import AIStockAlert
    from .farmer import Farmer
    from .order import Order
    from .product import Product
    from .rating import Rating
    from .refresh_token import RefreshToken
    from .sms_log import SmsLog


# ---------------------------------------------------------------------------
# Roles (DB stores int; app often wants names)
# ---------------------------------------------------------------------------
ROLE_ADMIN: int = 1
ROLE_FARMER: int = 2
ROLE_CUSTOMER: int = 3

_ROLE_INT_TO_NAME: dict[int, str] = {
    ROLE_ADMIN: "admin",
    ROLE_FARMER: "farmer",
    ROLE_CUSTOMER: "customer",
}
_ROLE_NAME_TO_INT: dict[str, int] = {
    "admin": ROLE_ADMIN,
    "farmer": ROLE_FARMER,
    "customer": ROLE_CUSTOMER,
}


def _role_as_int(value: Any) -> int:
    """Normalize role input to a safe int."""
    if isinstance(value, str):
        return _ROLE_NAME_TO_INT.get(value.strip().lower(), ROLE_CUSTOMER)
    try:
        return int(value)
    except Exception:
        return ROLE_CUSTOMER


def _module_exists(module_path: str) -> bool:
    """
    Mapper-safety helper:
    Only declare optional relationships if the target module exists on disk.
    """
    try:
        return importlib.util.find_spec(module_path) is not None
    except Exception:
        return False


_HAS_RATING = _module_exists("backend.models.rating")
_HAS_SMSLOG = _module_exists("backend.models.sms_log")
_HAS_AI_STOCK_ALERT = _module_exists("backend.models.ai_stock_alert")
_HAS_REFRESH_TOKEN = _module_exists("backend.models.refresh_token")
_HAS_FARMER_PROFILE = _module_exists("backend.models.farmer")


class User(db.Model):  # type: ignore[misc]
    """
    Core user model.

    Notes:
      • `role` is stored as INT in DB.
      • `role_name` gives the UI-friendly name.
      • Optional relationships are declared only when the module exists.
    """

    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_email_role", "email", "role"),
    )

    # ---------------------------------------------------------------------
    # Columns
    # ---------------------------------------------------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    full_name: Mapped[str] = mapped_column(String(200), nullable=False)

    phone: Mapped[str] = mapped_column(
        String(20),
        unique=True,
        index=True,
        nullable=False,
    )

    email: Mapped[str] = mapped_column(
        String(200),
        unique=True,
        index=True,
        nullable=False,
    )

    location: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)

    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    role: Mapped[int] = mapped_column(Integer, nullable=False, default=ROLE_CUSTOMER)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        default=func.now(),
        onupdate=func.now(),
    )

    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=False),
        nullable=True,
    )

    # ---------------------------------------------------------------------
    # Required relationships
    # ---------------------------------------------------------------------
    products: Mapped[list["Product"]] = relationship(
        "Product",
        back_populates="farmer",
        foreign_keys="Product.farmer_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    orders: Mapped[list["Order"]] = relationship(
        "Order",
        back_populates="buyer",
        foreign_keys="Order.buyer_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    # ---------------------------------------------------------------------
    # Optional relationships
    # ---------------------------------------------------------------------
    if _HAS_RATING:
        # REVIEWS AUTHORED BY THIS USER
        # IMPORTANT:
        # Rating has two FKs to users:
        #   - Rating.user_id
        #   - Rating.moderated_by
        # We must explicitly point this relationship at Rating.user_id.
        ratings: Mapped[list["Rating"]] = relationship(
            "Rating",
            back_populates="user",
            foreign_keys="Rating.user_id",
            passive_deletes=True,
        )

        # REVIEWS MODERATED BY THIS USER (admin governance)
        # This keeps the admin moderation link explicit and prevents mapper ambiguity.
        moderated_ratings: Mapped[list["Rating"]] = relationship(
            "Rating",
            back_populates="moderator",
            foreign_keys="Rating.moderated_by",
            passive_deletes=True,
        )

    if _HAS_SMSLOG:
        sms_logs: Mapped[list["SmsLog"]] = relationship(
            "SmsLog",
            back_populates="user",
            passive_deletes=True,
        )

    if _HAS_AI_STOCK_ALERT:
        ai_stock_alerts: Mapped[list["AIStockAlert"]] = relationship(
            "AIStockAlert",
            back_populates="farmer",
            foreign_keys="AIStockAlert.farmer_id",
            cascade="all, delete-orphan",
            passive_deletes=True,
        )

    if _HAS_REFRESH_TOKEN:
        refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
            "RefreshToken",
            back_populates="user",
            cascade="all, delete-orphan",
            passive_deletes=True,
        )

    if _HAS_FARMER_PROFILE:
        farmer_profile: Mapped[Optional["Farmer"]] = relationship(
            "Farmer",
            back_populates="user",
            uselist=False,
            cascade="all, delete-orphan",
            passive_deletes=True,
        )

    # ---------------------------------------------------------------------
    # Convenience properties
    # ---------------------------------------------------------------------
    @property
    def role_name(self) -> str:
        return _ROLE_INT_TO_NAME.get(
            _role_as_int(getattr(self, "role", ROLE_CUSTOMER)),
            "customer",
        )

    @property
    def is_admin(self) -> bool:
        return self.role_name == "admin"

    @property
    def is_farmer(self) -> bool:
        return self.role_name == "farmer"

    @property
    def is_customer(self) -> bool:
        return self.role_name == "customer"

    # ---------------------------------------------------------------------
    # Serialization
    # ---------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        role_int = _role_as_int(getattr(self, "role", ROLE_CUSTOMER))
        return {
            "id": str(self.id),
            "full_name": self.full_name,
            "phone": self.phone,
            "email": self.email,
            "location": self.location,
            "role": role_int,
            "role_name": self.role_name,
            "is_active": bool(self.is_active),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<User id={self.id} email={self.email} role={self.role_name}>"