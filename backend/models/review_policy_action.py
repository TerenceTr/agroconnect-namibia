# ============================================================================
# backend/models/review_policy_action.py — Review Policy Action Audit Model
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Dedicated moderation audit stream for review governance decisions.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from backend.database.db import db

if TYPE_CHECKING:
    from .rating import Rating
    from .user import User


class ReviewPolicyAction(db.Model):
    __tablename__ = "review_policy_actions"

    action_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    id = synonym("action_id")

    rating_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("ratings.rating_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    admin_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action_type: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    action_status: Mapped[str] = mapped_column(Text, nullable=False, default="applied", server_default=text("'applied'"), index=True)
    rationale: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column("metadata", JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), nullable=False, server_default=text("now()"), index=True)

    rating: Mapped["Rating"] = relationship("Rating", back_populates="policy_actions", lazy="selectin")
    admin: Mapped["User"] = relationship("User", lazy="selectin")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": str(self.action_id),
            "id": str(self.action_id),
            "rating_id": str(self.rating_id),
            "admin_id": str(self.admin_id),
            "action_type": self.action_type,
            "action_status": self.action_status,
            "rationale": self.rationale,
            "metadata": self.metadata_json or {},
            "metadata_json": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
