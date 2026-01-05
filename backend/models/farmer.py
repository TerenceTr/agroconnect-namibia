# ====================================================================
# backend/models/farmer.py — Farmer Profile (Optional Extension Table)
# ====================================================================
# FILE ROLE:
#   • Optional 1-to-1 extension table for farmer-specific fields
#     (farm_name, farm_description, etc.)
#   • Linked to User via user_id (unique) to enforce 1-to-1
#
# WHY THIS FILE EXISTS:
#   Keep "users" lean (auth + identity). Store role-specific fields here.
#
# OPTIONAL-TABLE SAFETY:
#   • Keeping this model in code is OK even if the DB table isn't migrated yet.
#   • The key is: User.farmer_profile MUST exist to satisfy back_populates
#     and avoid mapper crashes.
# ====================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.db import db

if TYPE_CHECKING:
    from .user import User


def utc_now_naive() -> datetime:
    """Naive UTC timestamp (best for DateTime(timezone=False))."""
    return datetime.utcnow()


class Farmer(db.Model):
    """
    Optional farmer profile data.

    NOTE:
      If your DB doesn't have this table yet, do not query Farmer until migrations run.
      Keeping the model defined is fine.
    """

    __tablename__ = "farmers"

    # ---------------- Identity ----------------
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ---------------- FK to users (1-to-1) ----------------
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,   # enforces 1-to-1 user <-> farmer_profile
        nullable=False,
        index=True,
    )

    # ---------------- Profile fields ----------------
    farm_name: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    farm_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        default=utc_now_naive,
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        default=utc_now_naive,
        onupdate=utc_now_naive,
        nullable=False,
    )

    # ---------------- Relationships ----------------
    user: Mapped["User"] = relationship(
        "User",
        back_populates="farmer_profile",
        lazy="select",
        passive_deletes=True,
    )

    # ---------------- Serialization ----------------
    def to_dict(self) -> dict[str, Optional[str]]:
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "farm_name": self.farm_name,
            "farm_description": self.farm_description,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
