# ============================================================================
# backend/models/sla_daily_snapshot.py — Daily SLA Snapshot (Aggregate)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores ONE row per day with overall moderation SLA stats (not per-admin).
#   Useful for audit-grade SLA charts (monthly trend, compliance reporting).
#
# NOTE:
#   Your codebase also contains a per-admin snapshot model
#   (backend/models/admin_sla_snapshot.py). This aggregate table is optional;
#   SLA charts can be computed on the fly if this table is absent.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Date, DateTime, Integer, Numeric
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db


class SlaDailySnapshot(db.Model):  # type: ignore[misc]
    """Aggregate daily SLA snapshot (overall, not per admin)."""

    __tablename__ = "sla_daily_snapshots"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    snapshot_date: Mapped[datetime] = mapped_column(
        Date,
        unique=True,
        nullable=False,
        index=True,
    )

    reviewed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Average turnaround (hours) for that day. Numeric avoids float drift.
    avg_hours: Mapped[float] = mapped_column(Numeric(6, 2), nullable=True)

    # Total breached items (turnaround > SLA target) for that day.
    breach_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        default=datetime.utcnow,
    )
