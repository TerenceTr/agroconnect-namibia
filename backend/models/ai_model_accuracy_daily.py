# ====================================================================
# backend/models/ai_model_accuracy_daily.py — Daily AI Accuracy Snapshot
# ====================================================================
# FILE ROLE:
#   Stores daily aggregated error metrics for AI models:
#     • mae, rmse, mape
#     • sample size n
#   Used by admin analytics dashboards and governance reporting.
#
# DB MATCH:
#   Table: ai_model_accuracy_daily
#   Columns: row_id, day, task, crop, model_version, n, mae, rmse, mape, computed_at
# ====================================================================

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Any, Dict

from sqlalchemy import BigInteger, Date, DateTime, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class AIModelAccuracyDaily(db.Model):
    __tablename__ = "ai_model_accuracy_daily"

    row_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)

    day: Mapped[date] = mapped_column(Date, nullable=False, index=True)

    task: Mapped[str] = mapped_column(Text, nullable=False)          # e.g. demand|price|supply
    crop: Mapped[str] = mapped_column(Text, nullable=False)          # e.g. maize|mahangu
    model_version: Mapped[str] = mapped_column(Text, nullable=False) # e.g. v1.0.0

    n: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    mae: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rmse: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    mape: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        index=True,
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "row_id": int(self.row_id),
            "day": self.day.isoformat(),
            "task": self.task,
            "crop": self.crop,
            "model_version": self.model_version,
            "n": int(self.n),
            "mae": float(self.mae),
            "rmse": float(self.rmse),
            "mape": float(self.mape),
            "computed_at": self.computed_at.isoformat() if self.computed_at else None,
        }
