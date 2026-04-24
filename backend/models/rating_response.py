# ============================================================================
# backend/models/rating_response.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores public farmer replies attached to verified customer reviews.
#
# IMPORTANT FIXES IN THIS VERSION:
#   ✅ Keeps relationship target name exactly "Rating"
#   ✅ Uses explicit foreign_keys for responder -> User
#   ✅ Keeps mapper-friendly relationship wiring for back_populates="responses"
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from backend.database.db import db

if TYPE_CHECKING:
    from .rating import Rating
    from .user import User


class RatingResponse(db.Model):
    __tablename__ = "rating_responses"

    response_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("public.uuid_generate_v4()"),
    )
    id = synonym("response_id")

    rating_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("ratings.rating_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    responder_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    responder_role: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="farmer",
        server_default=text("'farmer'"),
    )

    response_text: Mapped[str] = mapped_column(Text, nullable=False)

    is_public: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
        onupdate=datetime.utcnow,
    )

    rating: Mapped["Rating"] = relationship(
        "Rating",
        back_populates="responses",
        lazy="selectin",
    )

    responder: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[responder_user_id],
        lazy="selectin",
    )

    def to_dict(self) -> Dict[str, Any]:
        responder = getattr(self, "responder", None)
        responder_name = None
        if responder is not None:
            responder_name = (
                getattr(responder, "full_name", None)
                or getattr(responder, "name", None)
                or getattr(responder, "email", None)
            )

        return {
            "response_id": str(self.response_id),
            "id": str(self.response_id),
            "rating_id": str(self.rating_id),
            "responder_user_id": (
                str(self.responder_user_id) if self.responder_user_id else None
            ),
            "responder_role": self.responder_role,
            "responder_name": responder_name or "Farmer",
            "response_text": self.response_text,
            "is_public": bool(self.is_public),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<RatingResponse id={self.response_id} rating_id={self.rating_id}>"