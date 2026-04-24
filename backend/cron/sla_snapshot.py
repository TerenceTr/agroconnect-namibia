# ============================================================================
# backend/cron/sla_snapshot.py — Daily SLA Snapshot Job
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Runs once per day (cron) to persist per-admin SLA metrics for audit-grade
#   reporting and trend charts.
#
# USAGE:
#   python -m backend.cron.sla_snapshot
#
# PYRIGHT / PYLANCE NOTES:
#   ✅ Avoid model kwargs in constructors (type checker can’t see __init__ params)
#   ✅ With Mapped models, attribute assignments type-check properly
#   ✅ Convert float -> Decimal for Numeric DB fields
# ============================================================================

from __future__ import annotations

import uuid
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Optional, Tuple

from backend.app import create_app
from backend.database.db import db
from backend.models.admin_sla_snapshot import AdminSLADailySnapshot
from backend.services.sla_metrics import SLA_TARGET_HOURS, compute_admin_sla


def _day_window_utc(day: date) -> Tuple[datetime, datetime]:
    """Return UTC day window [00:00:00, 23:59:59.999999] for a date."""
    start_dt = datetime.combine(day, datetime.min.time())
    end_dt = datetime.combine(day, datetime.max.time())
    return start_dt, end_dt


def _to_uuid(v: Any) -> Optional[uuid.UUID]:
    if not v:
        return None
    try:
        return uuid.UUID(str(v))
    except Exception:
        return None


def _to_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def _to_decimal(v: Any, *, q: str) -> Optional[Decimal]:
    """
    Convert to Decimal (optionally quantized).
    Returns None if input is None/empty/unparseable.
    """
    if v is None:
        return None
    try:
        d = Decimal(str(v))
        return d.quantize(Decimal(q))
    except (InvalidOperation, ValueError):
        return None


def run_daily_sla_snapshot(*, for_day: Optional[date] = None) -> None:
    """
    Persist per-admin SLA metrics for a single day (default: yesterday).
    Upserts rows by (admin_id, snapshot_date).
    """
    target_day = for_day or (date.today() - timedelta(days=1))
    start_dt, end_dt = _day_window_utc(target_day)

    metrics = compute_admin_sla(start_dt=start_dt, end_dt=end_dt)

    for m in metrics:
        get = getattr(m, "get", None)
        if not callable(get):
            continue

        admin_id = _to_uuid(get("admin_id"))
        if not admin_id:
            continue

        reviewed = _to_int(get("reviewed_count"))
        breached = _to_int(get("breached_count"))
        met = max(0, reviewed - breached)

        avg_hours = _to_decimal(get("avg_review_hours"), q="0.01")  # Numeric(10,2)
        sla_percent = _to_decimal(get("sla_percent"), q="0.01") or Decimal("0.00")  # Numeric(5,2)

        existing = (
            db.session.query(AdminSLADailySnapshot)
            .filter(AdminSLADailySnapshot.admin_id == admin_id)
            .filter(AdminSLADailySnapshot.snapshot_date == target_day)
            .first()
        )

        if existing:
            existing.reviewed_count = reviewed
            existing.sla_met_count = met
            existing.sla_breached_count = breached
            existing.avg_review_hours = avg_hours
            existing.sla_percentage = sla_percent
        else:
            snap = AdminSLADailySnapshot()
            snap.admin_id = admin_id
            snap.snapshot_date = target_day
            snap.reviewed_count = reviewed
            snap.sla_met_count = met
            snap.sla_breached_count = breached
            snap.avg_review_hours = avg_hours
            snap.sla_percentage = sla_percent
            db.session.add(snap)

    db.session.commit()


if __name__ == "__main__":
    app = create_app()
    with app.app_context():
        run_daily_sla_snapshot()
        print(f"OK: SLA daily snapshot saved (target={SLA_TARGET_HOURS}h)")
