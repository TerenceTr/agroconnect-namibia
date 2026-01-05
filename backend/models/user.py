# ============================================================================
# backend/models/user.py — User Model (DB-ALIGNED + MAPPER-SAFE + PYLANCE-FRIENDLY)
# ============================================================================
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from .ai_stock_alert import AIStockAlert
    from .product import Product
    from .order import Order
    from .rating import Rating
    from .refresh_token import RefreshToken
    from .sms_log import SmsLog
    from .farmer import Farmer


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
    if isinstance(value, str):
        return _ROLE_NAME_TO_INT.get(value.strip().lower(), ROLE_CUSTOMER)
    try:
        return int(value)
    except Exception:
        return ROLE_CUSTOMER


class User(db.Model):  # type: ignore[misc]
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    phone: Mapped[str] = mapped_column(String(50), nullable=False)

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    location: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # DB: integer role
    role: Mapped[int] = mapped_column(Integer, nullable=False, default=ROLE_CUSTOMER)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), server_default=func.now(), onupdate=func.now(), nullable=False
    )

    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)

    # Relationships required by back_populates elsewhere
    products: Mapped[list["Product"]] = relationship(
        "Product", back_populates="farmer", cascade="all, delete-orphan", passive_deletes=True
    )
    orders: Mapped[list["Order"]] = relationship(
        "Order", back_populates="buyer", cascade="all, delete-orphan", passive_deletes=True
    )
    ratings: Mapped[list["Rating"]] = relationship(
        "Rating", back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )

    sms_logs: Mapped[list["SmsLog"]] = relationship("SmsLog", back_populates="user", passive_deletes=True)

    ai_stock_alerts: Mapped[list["AIStockAlert"]] = relationship(
        "AIStockAlert",
        back_populates="farmer",
        foreign_keys="AIStockAlert.farmer_id",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken", back_populates="user", cascade="all, delete-orphan", passive_deletes=True
    )

    farmer_profile: Mapped[Optional["Farmer"]] = relationship(
        "Farmer", back_populates="user", uselist=False, cascade="all, delete-orphan", passive_deletes=True
    )

    @property
    def role_name(self) -> str:
        return _ROLE_INT_TO_NAME.get(_role_as_int(getattr(self, "role", ROLE_CUSTOMER)), "customer")

    @property
    def is_admin(self) -> bool:
        return self.role_name == "admin"

    @property
    def is_farmer(self) -> bool:
        return self.role_name == "farmer"

    @property
    def is_customer(self) -> bool:
        return self.role_name == "customer"

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
        }


Index("ix_users_email_role", User.email, User.role)
