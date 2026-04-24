# ============================================================================
# backend/models/admin_sla_snapshot.py — Admin SLA Daily Snapshot (Typed)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores daily per-admin SLA metrics used for charts + audit reporting.
#
# PYRIGHT FIX:
#   Use SQLAlchemy 2.x Mapped + mapped_column so assignments are typed correctly.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal
from typing import Optional

from sqlalchemy import Date, Index, Integer, Numeric
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db


class AdminSLADailySnapshot(db.Model):  # type: ignore[misc]
    __tablename__ = "admin_sla_daily_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    admin_id: Mapped[uuid.UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)

    reviewed_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sla_met_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sla_breached_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Stored as Numeric; cron converts float->Decimal
    avg_review_hours: Mapped[Optional[Decimal]] = mapped_column(Numeric(10, 2), nullable=True)
    sla_percentage: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False, default=Decimal("0.00"))

    __table_args__ = (
        Index("ux_admin_sla_day", "admin_id", "snapshot_date", unique=True),
    )
