# ============================================================================
# backend/models/review_issue_link.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Join model linking a review/rating to one or more complaint taxonomy items.
#
# PHASE 4A:
#   ✅ Supports multiple issue tags per review
#   ✅ Tracks who tagged the issue
#   ✅ Supports confidence scoring and primary issue marking
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict

from sqlalchemy import Boolean, DateTime, ForeignKey, Numeric, Text, UniqueConstraint, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db


class ReviewIssueLink(db.Model):
    __tablename__ = "review_issue_links"
    __table_args__ = (
        UniqueConstraint("rating_id", "taxonomy_id", name="uq_review_issue_links_rating_taxonomy"),
    )

    review_issue_link_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    rating_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("ratings.rating_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    taxonomy_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("complaint_taxonomy.taxonomy_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    detected_by: Mapped[str] = mapped_column(String(30), nullable=False, default="customer", server_default="customer")
    tagged_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    confidence_score: Mapped[float] = mapped_column(
        Numeric(5, 4),
        nullable=False,
        default=1.0,
        server_default="1.0000",
    )

    is_primary: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        default=func.now(),
        server_default=func.now(),
        onupdate=func.now(),
    )

    rating = relationship("Rating", lazy="selectin")
    taxonomy = relationship("ComplaintTaxonomy", back_populates="review_issue_links", lazy="selectin")
    tagged_by_user = relationship("User", foreign_keys=[tagged_by_user_id], lazy="selectin")

    def to_dict(self) -> Dict[str, Any]:
        taxonomy = getattr(self, "taxonomy", None)
        return {
            "review_issue_link_id": str(self.review_issue_link_id),
            "rating_id": str(self.rating_id),
            "taxonomy_id": str(self.taxonomy_id),
            "detected_by": self.detected_by,
            "tagged_by_user_id": str(self.tagged_by_user_id) if self.tagged_by_user_id else None,
            "confidence_score": float(self.confidence_score or 0),
            "is_primary": bool(self.is_primary),
            "notes": self.notes,
            "taxonomy": taxonomy.to_dict() if taxonomy is not None else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ReviewIssueLink rating={self.rating_id} taxonomy={self.taxonomy_id}>"
