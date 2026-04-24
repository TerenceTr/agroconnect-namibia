# ============================================================================
# backend/routes/admin_sla.py — Admin SLA Leaderboard
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Dedicated per-admin moderation SLA leaderboard endpoint.
#
# ROUTE (url_prefix="/api/admin"):
#   GET /api/admin/sla/leaderboard?period=day|week|month
#
# DESIGN:
#   ✅ Uses backend.services.sla_metrics as the single source of truth
#   ✅ Keeps output backward-friendly for existing frontend consumers
# ============================================================================

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional, Tuple

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response

from backend.models.user import ROLE_ADMIN, User
from backend.services.sla_metrics import SLA_TARGET_HOURS, compute_admin_sla
from backend.utils.require_auth import require_access_token

admin_sla_bp = Blueprint("admin_sla", __name__)


def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _current_user() -> Optional[User]:
    u = getattr(g, "current_user", None)
    if isinstance(u, User):
        return u

    u2 = getattr(request, "current_user", None)
    if isinstance(u2, User):
        return u2

    return None


def _admin_guard() -> Optional[Response]:
    user = _current_user()
    if user is None:
        return _json({"success": False, "message": "Authentication required"}, 401)

    if int(getattr(user, "role", 0) or 0) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)

    return None


def _resolve_period_window(period: str) -> Tuple[str, datetime, datetime]:
    now = datetime.utcnow()
    p = (period or "month").strip().lower()

    if p == "day":
        return "day", now - timedelta(days=1), now
    if p == "week":
        return "week", now - timedelta(days=7), now

    return "month", now - timedelta(days=30), now


@admin_sla_bp.get("/sla/leaderboard")
@require_access_token
def sla_leaderboard() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    period, start_dt, end_dt = _resolve_period_window(request.args.get("period", "month"))

    rows = compute_admin_sla(start_dt=start_dt, end_dt=end_dt)

    items: list[dict[str, Any]] = []
    for row in rows:
        reviewed = int(row.get("reviewed_count") or 0)
        breached = int(row.get("breached_count") or 0)
        met = max(reviewed - breached, 0)
        avg_hours = float(row.get("avg_review_hours") or 0.0)
        sla_percentage = float(row.get("sla_percent") or row.get("sla_score") or 0.0)

        items.append(
            {
                "admin_id": row.get("admin_id"),
                "admin_name": row.get("admin_name") or "Admin",
                "reviewed_count": reviewed,
                "avg_review_hours": round(avg_hours, 2),
                "sla_met": met,
                "sla_breached": breached,
                "sla_percentage": round(sla_percentage, 2),
            }
        )

    return _json(
        {
            "success": True,
            "period": period,
            "target_hours": int(SLA_TARGET_HOURS),
            "start": start_dt.isoformat(),
            "end": end_dt.isoformat(),
            "items": items,
        }
    )