# ============================================================================
# backend/models/complaint_taxonomy.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Controlled complaint taxonomy used to classify review issues.
#
# PHASE 4A:
#   ✅ Master taxonomy table for complaint categories
#   ✅ Severity weighting for later repeat-issue detection
#   ✅ Parent groups for dashboard aggregation
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db


class ComplaintTaxonomy(db.Model):
    __tablename__ = "complaint_taxonomy"

    taxonomy_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    code: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    label: Mapped[str] = mapped_column(String(150), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_group: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    severity_weight: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")

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

    # Linked review issues.
    review_issue_links = relationship(
        "ReviewIssueLink",
        back_populates="taxonomy",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "taxonomy_id": str(self.taxonomy_id),
            "code": self.code,
            "label": self.label,
            "description": self.description,
            "parent_group": self.parent_group,
            "severity_weight": int(self.severity_weight),
            "is_active": bool(self.is_active),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:  # pragma: no cover
        return f"<ComplaintTaxonomy {self.code}>"
