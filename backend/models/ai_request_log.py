# ====================================================================
# backend/models/ai_request_log.py — AI Request Audit Log (Governance)
# ====================================================================
# FILE ROLE:
#   Governance-grade logging for AI requests:
#     • endpoint called
#     • input/output payloads (JSONB)
#     • model_version + cache flag
#     • created_at timestamp
#
# DB MATCH (agroconnect_db.sql):
#   Table: ai_request_log
#   Columns:
#     request_id UUID PK
#     endpoint TEXT
#     input_json JSONB
#     output_json JSONB NULL
#     model_version TEXT
#     cached BOOL (default false)
#     created_at TIMESTAMPTZ
# ====================================================================

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AIRequestLog(db.Model):
    __tablename__ = "ai_request_log"

    request_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    endpoint: Mapped[str] = mapped_column(Text, nullable=False, index=True)

    input_json: Mapped[dict] = mapped_column(JSONB, nullable=False)
    output_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    model_version: Mapped[str] = mapped_column(Text, nullable=False)
    cached: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": str(self.request_id),
            "endpoint": self.endpoint,
            "input_json": self.input_json,
            "output_json": self.output_json,
            "model_version": self.model_version,
            "cached": bool(self.cached),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
