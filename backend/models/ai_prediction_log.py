# ====================================================================
# backend/models/ai_prediction_log.py — AI Prediction Log (Error Tracking)
# ====================================================================
# FILE ROLE:
#   Stores prediction outputs and (optional) actual values for evaluation:
#     • predicted_value, actual_value
#     • entity_id (what was predicted for)
#     • timestamps + metadata
#
# DB MATCH (agroconnect_db.sql):
#   Table: ai_prediction_logs
#   Columns:
#     log_id UUID PK
#     task TEXT
#     crop TEXT
#     model_version TEXT
#     entity_id UUID
#     predicted_value DOUBLE
#     actual_value DOUBLE NULL
#     predicted_at TIMESTAMPTZ
#     actual_at TIMESTAMPTZ NULL
#     meta JSONB NULL
# ====================================================================

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, Float, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AIPredictionLog(db.Model):
    __tablename__ = "ai_prediction_logs"

    log_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    task: Mapped[str] = mapped_column(Text, nullable=False)
    crop: Mapped[str] = mapped_column(Text, nullable=False)
    model_version: Mapped[str] = mapped_column(Text, nullable=False)

    entity_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)

    predicted_value: Mapped[float] = mapped_column(Float, nullable=False)
    actual_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    predicted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, index=True
    )
    actual_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    meta: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": str(self.log_id),
            "task": self.task,
            "crop": self.crop,
            "model_version": self.model_version,
            "entity_id": str(self.entity_id),
            "predicted_value": float(self.predicted_value),
            "actual_value": float(self.actual_value) if self.actual_value is not None else None,
            "predicted_at": self.predicted_at.isoformat() if self.predicted_at else None,
            "actual_at": self.actual_at.isoformat() if self.actual_at else None,
            "meta": self.meta,
        }
