# ============================================================================
# backend/models/rating_flag.py — Review Flag Model (Phase 3)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores customer/admin moderation flags raised against reviews.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from backend.database.db import db

if TYPE_CHECKING:
    from .rating import Rating
    from .user import User


class RatingFlag(db.Model):
    __tablename__ = "rating_flags"

    flag_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    id = synonym("flag_id")

    rating_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("ratings.rating_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    flagged_by_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reason_code: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="open", server_default=text("'open'"), index=True)
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, server_default=text("now()"), index=True)

    rating: Mapped["Rating"] = relationship("Rating", back_populates="flags", lazy="selectin")
    flagged_by_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[flagged_by_user_id], lazy="selectin")
    reviewer: Mapped[Optional["User"]] = relationship("User", foreign_keys=[reviewed_by], lazy="selectin")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flag_id": str(self.flag_id),
            "id": str(self.flag_id),
            "rating_id": str(self.rating_id),
            "flagged_by_user_id": str(self.flagged_by_user_id) if self.flagged_by_user_id else None,
            "reason_code": self.reason_code,
            "notes": self.notes,
            "status": self.status,
            "reviewed_by": str(self.reviewed_by) if self.reviewed_by else None,
            "reviewed_at": self.reviewed_at.isoformat() if self.reviewed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
