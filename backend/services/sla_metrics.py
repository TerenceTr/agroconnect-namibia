# ============================================================================
# backend/services/sla_metrics.py — SLA Computation Helpers
# ----------------------------------------------------------------------------
# FILE ROLE:
#   • Compute moderation SLA metrics per admin (leaderboard)
#   • Compute overall SLA summary + daily snapshot series (for charts)
#   • Used by: admin analytics endpoint + cron snapshot job
#
# DESIGN:
#   • Query-safe: uses mapped columns/synonyms (Product.product_id / Product.id)
#   • Defensive: failures return empty/None fields instead of crashing the API
# ============================================================================

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional

from sqlalchemy import Date, case, func

from backend.database.db import db
from backend.models.product import Product
from backend.models.user import User


SLA_TARGET_HOURS = 48  # business rule


def compute_admin_sla(*, start_dt: datetime, end_dt: datetime) -> List[Dict[str, Any]]:
    """Compute per-admin SLA between start_dt and end_dt.

    Output is stable and explainable:
      - reviewed_count, breached_count
      - avg_review_hours (rounded to 2dp)
      - sla_score (0..100)
      - sla_percent (0..100)

    Notes:
      • Uses reviewed_at timestamp window (when moderation happened)
      • Uses Product.created_at as submission time baseline
    """

    # Always count the real mapped column to avoid @property issues.
    product_pk = getattr(Product, "product_id", None) or getattr(Product, "id", None)

    # Hours between submission and review.
    hours_expr = func.extract("epoch", Product.reviewed_at - Product.created_at) / 3600.0

    rows = (
        db.session.query(
            Product.reviewed_by.label("admin_id"),
            func.count(product_pk).label("reviewed_count"),
            func.avg(hours_expr).label("avg_hours"),
            func.sum(
                case(
                    (hours_expr > float(SLA_TARGET_HOURS), 1),
                    else_=0,
                )
            ).label("breached_count"),
        )
        .filter(Product.reviewed_at.isnot(None))
        .filter(Product.reviewed_by.isnot(None))
        .filter(Product.created_at.isnot(None))
        .filter(Product.reviewed_at.between(start_dt, end_dt))
        .group_by(Product.reviewed_by)
        .all()
    )

    results: List[Dict[str, Any]] = []
    for r in rows:
        admin = db.session.get(User, r.admin_id)
        if not admin:
            # Admin user deleted; skip for cleanliness.
            continue

        reviewed = int(r.reviewed_count or 0)
        breached = int(r.breached_count or 0)

        avg_hours_raw = Decimal(str(r.avg_hours or 0))
        avg_hours = float(avg_hours_raw.quantize(Decimal("0.01")))

        sla_percent = _sla_score(reviewed, breached)

        results.append(
            {
                "admin_id": str(r.admin_id),
                "admin_name": getattr(admin, "full_name", None)
                or getattr(admin, "name", None)
                or "Admin",
                "reviewed_count": reviewed,
                "breached_count": breached,
                "avg_review_hours": avg_hours,
                # Keep both keys to be frontend/backward friendly.
                "sla_score": sla_percent,
                "sla_percent": sla_percent,
            }
        )

    # Sort by best SLA% first, then fastest avg hours.
    return sorted(
        results,
        key=lambda x: (-int(x.get("sla_score") or 0), float(x.get("avg_review_hours") or 0.0)),
    )


def build_sla_payload(
    *,
    start_dt: Optional[datetime] = None,
    end_dt: Optional[datetime] = None,
    window_days: int = 30,
) -> Dict[str, Any]:
    """Build SLA payload for analytics endpoints.

    Returns (always):
      {
        target_hours,
        leaderboard: [...],
        summary: {total_reviewed, avg_review_hours, sla_percent, breached_count},
        daily_snapshot: [{date, reviewed_count, breached_count, avg_review_hours, sla_percent}, ...]
      }

    Defensive behavior:
      • If tables/columns are missing -> returns safe empty structures.
    """

    now = end_dt or datetime.utcnow()
    start = start_dt or (now - timedelta(days=int(window_days)))

    payload: Dict[str, Any] = {
        "target_hours": int(SLA_TARGET_HOURS),
        "leaderboard": [],
        "summary": {
            "total_reviewed": 0,
            "breached_count": 0,
            "avg_review_hours": None,
            "sla_percent": None,
        },
        "daily_snapshot": [],
    }

    try:
        leaderboard = compute_admin_sla(start_dt=start, end_dt=now)

        # Add rank for UI convenience.
        for idx, row in enumerate(leaderboard, start=1):
            row["rank"] = idx

        payload["leaderboard"] = leaderboard

        # Summary aggregates (windowed).
        totals = _compute_overall_sla_summary(start_dt=start, end_dt=now)
        payload["summary"].update(totals)

        # Snapshot series (daily) for charts (windowed).
        payload["daily_snapshot"] = _compute_daily_series(start_dt=start, end_dt=now)

        return payload
    except Exception:
        return payload


def _compute_overall_sla_summary(*, start_dt: datetime, end_dt: datetime) -> Dict[str, Any]:
    """Overall SLA summary across all reviewed items in the window."""

    product_pk = getattr(Product, "product_id", None) or getattr(Product, "id", None)
    hours_expr = func.extract("epoch", Product.reviewed_at - Product.created_at) / 3600.0

    reviewed_count = (
        db.session.query(func.count(product_pk))
        .filter(Product.reviewed_at.isnot(None))
        .filter(Product.created_at.isnot(None))
        .filter(Product.reviewed_at.between(start_dt, end_dt))
        .scalar()
    )
    reviewed = int(reviewed_count or 0)

    breached_count = (
        db.session.query(
            func.sum(
                case(
                    (hours_expr > float(SLA_TARGET_HOURS), 1),
                    else_=0,
                )
            )
        )
        .filter(Product.reviewed_at.isnot(None))
        .filter(Product.created_at.isnot(None))
        .filter(Product.reviewed_at.between(start_dt, end_dt))
        .scalar()
    )
    breached = int(breached_count or 0)

    avg_hours = (
        db.session.query(func.avg(hours_expr))
        .filter(Product.reviewed_at.isnot(None))
        .filter(Product.created_at.isnot(None))
        .filter(Product.reviewed_at.between(start_dt, end_dt))
        .scalar()
    )

    avg_review_hours = float(Decimal(str(avg_hours or 0)).quantize(Decimal("0.01"))) if reviewed > 0 else None
    sla_percent = _sla_score(reviewed, breached) if reviewed > 0 else None

    return {
        "total_reviewed": reviewed,
        "breached_count": breached,
        "avg_review_hours": avg_review_hours,
        "sla_percent": sla_percent,
    }


def _compute_daily_series(*, start_dt: datetime, end_dt: datetime) -> List[Dict[str, Any]]:
    """Daily time-series of SLA performance for the window.

    Computed directly from Product timestamps so it works even without snapshot tables.
    """

    hours_expr = func.extract("epoch", Product.reviewed_at - Product.created_at) / 3600.0
    day_expr = func.cast(Product.reviewed_at, Date)

    rows = (
        db.session.query(
            day_expr.label("day"),
            func.count(getattr(Product, "product_id", None) or getattr(Product, "id", None)).label("reviewed_count"),
            func.avg(hours_expr).label("avg_hours"),
            func.sum(
                case(
                    (hours_expr > float(SLA_TARGET_HOURS), 1),
                    else_=0,
                )
            ).label("breached_count"),
        )
        .filter(Product.reviewed_at.isnot(None))
        .filter(Product.created_at.isnot(None))
        .filter(Product.reviewed_at.between(start_dt, end_dt))
        .group_by(day_expr)
        .order_by(day_expr)
        .all()
    )

    series: List[Dict[str, Any]] = []
    for d, reviewed_count, avg_hours, breached_count in rows:
        reviewed = int(reviewed_count or 0)
        breached = int(breached_count or 0)
        avg_review_hours = float(Decimal(str(avg_hours or 0)).quantize(Decimal("0.01"))) if reviewed > 0 else None
        sla_percent = _sla_score(reviewed, breached) if reviewed > 0 else None

        series.append(
            {
                "date": d.isoformat() if hasattr(d, "isoformat") else str(d),
                "reviewed_count": reviewed,
                "breached_count": breached,
                "avg_review_hours": avg_review_hours,
                "sla_percent": sla_percent,
            }
        )

    return series


def _sla_score(reviewed: int, breached: int) -> int:
    """Simple SLA score (% of reviews within the SLA target)."""
    if reviewed <= 0:
        return 0
    within = max(0, reviewed - max(0, breached))
    return max(0, min(100, int(round((within / reviewed) * 100))))
