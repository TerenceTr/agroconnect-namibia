# ====================================================================
# backend/routes/admin_analytics.py — Admin Analytics Summary (JWT)
# --------------------------------------------------------------------
# FILE ROLE:
#   Provides compact analytics summary for admin dashboards.
#
# ROUTE (registered with url_prefix="/api/admin"):
#   GET /api/admin/analytics/summary
#
# FIX INCLUDED:
#   Pylance/Pyright error:
#     "Argument of type 'property' cannot be assigned to ... expression"
#   happens when code passes @property attributes into SQLAlchemy (e.g. Product.id
#   implemented as @property). This version only uses query-safe mapped columns.
# ====================================================================

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional, cast

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response

from sqlalchemy import Date, func, select
from sqlalchemy import cast as sa_cast

from backend.database.db import db
from backend.models.order import Order
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, User
from backend.utils.require_auth import require_access_token

try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment,misc]

admin_analytics_bp = Blueprint("admin_analytics", __name__)


def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return cast(Response, resp)


def _current_user() -> Optional[User]:
    """Read current user from g or request (supports different auth middlewares)."""
    u = getattr(g, "current_user", None)
    if isinstance(u, User):
        return u
    u2 = getattr(request, "current_user", None)
    if isinstance(u2, User):
        return u2
    return None


def _admin_guard() -> Optional[Response]:
    """Return an error response if not admin; otherwise None."""
    u = _current_user()
    if u is None:
        return _json({"success": False, "message": "Authentication required"}, 401)
    if int(getattr(u, "role", 0) or 0) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)
    return None


@admin_analytics_bp.route("/analytics/summary", methods=["GET"])
@require_access_token
def summary() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    window_days = 30
    since_dt = datetime.utcnow() - timedelta(days=window_days)

    # ----------------------------
    # Orders by status (all-time + last 30 days)
    # ----------------------------
    # Use query-safe mapped columns (avoid @property aliases)
    order_id_col: Any = getattr(Order, "id", None) or getattr(Order, "order_id", None)
    order_date_col: Any = getattr(Order, "order_date", None) or getattr(Order, "created_at", None)

    o_rows = db.session.execute(
        select(Order.status, func.count(order_id_col)).group_by(Order.status)
    ).all()

    orders_by_status: dict[str, int] = {
        (str(status).strip().lower() if status is not None else "unknown"): int(count or 0)
        for status, count in o_rows
    }

    orders_by_status_window: dict[str, int] = {}
    if order_date_col is not None:
        o30_rows = db.session.execute(
            select(Order.status, func.count(order_id_col))
            .where(order_date_col >= since_dt)
            .group_by(Order.status)
        ).all()

        orders_by_status_window = {
            (str(status).strip().lower() if status is not None else "unknown"): int(count or 0)
            for status, count in o30_rows
        }

    # ----------------------------
    # Products by status (all-time)
    # ----------------------------
    # Product.id is a mapped column in the updated model (NOT a @property)
    p_rows = db.session.execute(
        select(Product.status, func.count(Product.id)).group_by(Product.status)
    ).all()

    products_by_status: dict[str, int] = {
        (str(status).strip().lower() if status is not None else "unknown"): int(count or 0)
        for status, count in p_rows
    }

    # ----------------------------
    # Ratings trend (optional)
    # ----------------------------
    ratings_trend: list[dict[str, Any]] = []
    avg_rating = 0.0

    if Rating is not None:
        rating_id_col: Any = getattr(Rating, "id", None)
        rating_score_col: Any = getattr(Rating, "rating_score", None)
        rating_date_col: Any = getattr(Rating, "created_at", None)

        if rating_id_col is not None and rating_score_col is not None and rating_date_col is not None:
            d_expr = sa_cast(rating_date_col, Date)

            r_rows = db.session.execute(
                select(
                    d_expr.label("date"),
                    func.count(rating_id_col).label("count"),
                    func.avg(rating_score_col).label("avg"),
                )
                .where(rating_date_col >= since_dt)
                .group_by(d_expr)
                .order_by(d_expr)
            ).all()

            for d, c, a in r_rows:
                ratings_trend.append(
                    {
                        "date": d.isoformat() if hasattr(d, "isoformat") else str(d),
                        "count": int(c or 0),
                        "avg": float(a or 0.0),
                    }
                )

            avg_val = db.session.execute(select(func.avg(rating_score_col))).scalar()
            avg_rating = float(avg_val or 0.0)

    return _json(
        {
            "window_days": window_days,
            "orders_by_status": orders_by_status,
            "orders_by_status_window": orders_by_status_window,
            "products_by_status": products_by_status,
            "avg_rating": avg_rating,
            "ratings_trend": ratings_trend,
        }
    )
