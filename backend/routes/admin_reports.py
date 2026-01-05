# ============================================================================
# backend/routes/admin_reports.py — Admin Analytics & Reporting (Access JWT)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin-only analytics endpoints used by dashboards/reports:
#     • GET /overview   ✅ REQUIRED BY UI (AdminDashboard)
#     • GET /export     (optional, future)
#
# KEY FIXES (THIS VERSION):
#   • Fixes Pyright "int(None)" error by guarding role parsing in _is_admin()
#   • Pylance-friendly Flask submodule imports (Blueprint/request/jsonify)
#   • Query-safe SQL expressions: use mapped columns (Order.id, OrderItem.id)
#     NOT @property aliases like Order.order_id
#   • Recent orders include a readable product label from first order item
# ============================================================================

from __future__ import annotations

from datetime import date, datetime, time, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import func
from sqlalchemy.orm import selectinload

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import User
from backend.utils.require_auth import require_access_token

# Optional tables (only if present in your codebase)
try:
    from backend.models.rating import Rating  # type: ignore
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]

admin_reports_bp = Blueprint("admin_reports", __name__)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def _json(success: bool, message: Optional[str] = None, **kwargs: Any) -> Response:
    """Small JSON helper for consistent API responses."""
    payload: Dict[str, Any] = {"success": success}
    if message:
        payload["message"] = message
    payload.update(kwargs)
    return jsonify(payload)


def _current_user() -> Optional[User]:
    """
    require_access_token injects request.current_user.
    Use getattr so Pyright doesn't complain about request having dynamic attrs.
    """
    u = getattr(request, "current_user", None)
    return u if isinstance(u, User) else None


def _safe_int(value: Any) -> Optional[int]:
    """
    Convert value to int safely.

    Why this exists:
      Pyright complains about int(None). This returns None instead of crashing.
    """
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _is_admin(user: User) -> bool:
    """
    Determine admin access robustly.

    Order of preference:
      1) User.is_admin (property/helper)
      2) User.role_name == "admin" (string helper)
      3) Fallback: int role mapping (1=admin)
    """
    # 1) Preferred: explicit helper on your User model
    if bool(getattr(user, "is_admin", False)):
        return True

    # 2) Preferred: role_name helper ("admin"|"farmer"|"customer")
    rn = getattr(user, "role_name", None)
    if isinstance(rn, str) and rn.strip().lower() == "admin":
        return True

    # 3) Fallback: DB integer role convention (1=admin)
    role_int = _safe_int(getattr(user, "role", None))
    return role_int == 1


def _admin_only() -> Optional[tuple[Response, int]]:
    """
    Gatekeeper:
      - returns (json, status) if blocked
      - returns None if allowed
    """
    user = _current_user()
    if user is None:
        return _json(False, "Unauthorized"), 401
    if not _is_admin(user):
        return _json(False, "Forbidden"), 403
    return None


# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@admin_reports_bp.get("/overview")
@require_access_token
def overview() -> Response:  # type: ignore[no-untyped-def]
    """
    Admin dashboard overview data.

    Returns:
      totals: users/products/orders/revenue/pending
      charts: daily series (orders, registrations, optional ratings)
      recent_orders: last N orders with customer + product label
    """
    denied = _admin_only()
    if denied:
        resp, status = denied
        resp.status_code = status
        return resp

    # -----------------------------
    # Totals
    # -----------------------------
    total_users = db.session.query(func.count(User.id)).scalar() or 0
    total_products = db.session.query(func.count(Product.product_id)).scalar() or 0

    # IMPORTANT:
    #   Order.order_id is a @property alias in your model; don't use it in SQL.
    #   Use Order.id (mapped column -> orders.order_id).
    total_orders = db.session.query(func.count(Order.id)).scalar() or 0

    revenue_total = db.session.query(func.coalesce(func.sum(Order.order_total), 0)).scalar() or 0
    revenue_total_f = float(revenue_total) if isinstance(revenue_total, Decimal) else float(revenue_total or 0)

    pending_products = (
        db.session.query(func.count(Product.product_id))
        .filter(Product.status == "pending")
        .scalar()
        or 0
    )

    # -----------------------------
    # Recent orders
    # -----------------------------
    recent_orders: List[Dict[str, Any]] = []
    recent: List[Order] = (
        db.session.query(Order)
        .order_by(Order.order_date.desc())
        .limit(8)
        .all()
    )

    for o in recent:
        # First line item per order (use mapped UUID column: o.id)
        first_item: Optional[OrderItem] = (
            db.session.query(OrderItem)
            .options(selectinload(OrderItem.product))
            .filter(OrderItem.order_id == o.id)
            .order_by(OrderItem.created_at.asc())
            .first()
        )

        product_label = first_item.to_dict().get("product_name") if first_item else None

        item_count = (
            db.session.query(func.count(OrderItem.id))
            .filter(OrderItem.order_id == o.id)
            .scalar()
            or 0
        )

        d = o.to_dict(include_items=False)
        d["product_name"] = product_label
        d["item_count"] = int(item_count)
        recent_orders.append(d)

    # -----------------------------
    # Charts (last 14 days)
    # -----------------------------
    today = date.today()
    start_day = today - timedelta(days=13)

    # Use tz-naive datetime (DB column is timezone=False)
    start_dt = datetime.combine(start_day, time.min)

    # Daily order counts
    order_day = func.date(Order.order_date)
    daily_orders_rows = (
        db.session.query(order_day, func.count(Order.id))
        .filter(Order.order_date >= start_dt)
        .group_by(order_day)
        .order_by(order_day)
        .all()
    )
    daily_orders_map = {str(d): int(c) for d, c in daily_orders_rows}

    daily_orders = [
        {"date": str(start_day + timedelta(days=i)), "count": daily_orders_map.get(str(start_day + timedelta(days=i)), 0)}
        for i in range(14)
    ]

    # Daily registrations
    reg_day = func.date(User.created_at)
    daily_regs_rows = (
        db.session.query(reg_day, func.count(User.id))
        .filter(User.created_at >= start_dt)
        .group_by(reg_day)
        .order_by(reg_day)
        .all()
    )
    daily_regs_map = {str(d): int(c) for d, c in daily_regs_rows}

    daily_registrations = [
        {"date": str(start_day + timedelta(days=i)), "count": daily_regs_map.get(str(start_day + timedelta(days=i)), 0)}
        for i in range(14)
    ]

    # Optional ratings chart
    daily_ratings: List[Dict[str, Any]] = []
    if Rating is not None:
        rating_day = func.date(Rating.created_at)
        daily_ratings_rows = (
            db.session.query(rating_day, func.count(Rating.id))
            .filter(Rating.created_at >= start_dt)
            .group_by(rating_day)
            .order_by(rating_day)
            .all()
        )
        daily_ratings_map = {str(d): int(c) for d, c in daily_ratings_rows}

        daily_ratings = [
            {"date": str(start_day + timedelta(days=i)), "count": daily_ratings_map.get(str(start_day + timedelta(days=i)), 0)}
            for i in range(14)
        ]

    return _json(
        True,
        totals={
            "total_users": int(total_users),
            "total_products": int(total_products),
            "total_orders": int(total_orders),
            "revenue_total": revenue_total_f,
            "pending_products": int(pending_products),
        },
        charts={
            "daily_orders": daily_orders,
            "daily_registrations": daily_registrations,
            "daily_ratings": daily_ratings,
        },
        recent_orders=recent_orders,
    )
