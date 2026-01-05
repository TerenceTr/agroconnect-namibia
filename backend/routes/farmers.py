# ============================================================================
# backend/routes/farmers.py — Farmer APIs (Profile + Overview Dashboard)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Farmer-facing endpoints:
#     • Farmer profile lookup (safe even if optional farmers table is missing)
#     • Farmer dashboard "Overview" endpoint used by FarmerDashboard.jsx
#
# WHY THIS FILE WAS UPDATED:
#   • Multi-item orders: farmer KPIs must aggregate via:
#       orders -> order_items -> products
#   • Fix Pylance/Pyright errors:
#       - select(Farmer) with Farmer possibly None
#       - Farmer.user_id attribute when Farmer is optional
#       - Rating.rating_id attribute unknown
#       - cast(Order.id, db.String) invalid type engine
#
# ROUTES (mounted by registry at /api/farmer and /api/farmers):
#   GET  /me
#   GET  /<farmer_id>
#   GET  /overview
# ============================================================================

from __future__ import annotations

from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import Date, String, cast as sa_cast, desc, func, or_, select

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_FARMER, User
from backend.security import token_required

# Ratings exist in your DB dump, but keep optional safety.
try:
    from backend.models.rating import Rating as RatingModel
except Exception:  # pragma: no cover
    RatingModel = None  # type: ignore[assignment]

# Optional farmers extension table (NOT present in your DB dump by default).
try:
    from backend.models.farmer import Farmer as FarmerModel
except Exception:  # pragma: no cover
    FarmerModel = None  # type: ignore[assignment]


farmers_bp = Blueprint("farmers", __name__)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _utc_now_naive() -> datetime:
    """DB uses timestamp without timezone (naive)."""
    return datetime.utcnow()


def _to_uuid(value: Any) -> Optional[UUID]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return UUID(raw)
    except Exception:
        return None


def _to_int(value: Any, default: int) -> int:
    raw = str(value or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _to_decimal(value: Any, default: Decimal) -> Decimal:
    raw = str(value or "").strip()
    if not raw:
        return default
    try:
        return Decimal(raw)
    except Exception:
        return default


def _json_error(message: str, status: int) -> Any:
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


def _current_user() -> Optional[User]:
    u = getattr(request, "current_user", None)
    return u if isinstance(u, User) else None


def _safe_float(x: Any) -> float:
    try:
        return float(x)
    except Exception:
        return 0.0


# ----------------------------------------------------------------------------
# Profile endpoints (safe even without optional "farmers" table)
# ----------------------------------------------------------------------------
@farmers_bp.get("/me", strict_slashes=False)
@token_required
def farmer_me() -> Any:
    user = _current_user()
    if not user:
        return _json_error("Unauthorized", 401)

    if getattr(user, "role", None) not in (ROLE_FARMER, ROLE_ADMIN):
        return _json_error("Farmer access required", 403)

    payload: Dict[str, Any] = {
        "id": str(user.id),
        "full_name": user.full_name,
        "email": user.email,
        "phone": user.phone,
        "location": user.location,
        "role": user.role,
        "farmer_profile": None,
    }

    # Optional extension profile (only if model exists)
    if FarmerModel is not None:
        try:
            # Use getattr for type-checker + runtime safety
            user_id_col = getattr(FarmerModel, "user_id")
            prof = db.session.execute(  # type: ignore[attr-defined]
                select(FarmerModel).where(user_id_col == user.id)
            ).scalar_one_or_none()
            payload["farmer_profile"] = prof.to_dict() if prof else None
        except Exception:
            payload["farmer_profile"] = None

    return jsonify({"success": True, "farmer": payload})


@farmers_bp.get("/<string:farmer_id>", strict_slashes=False)
@token_required
def get_farmer(farmer_id: str) -> Any:
    user = _current_user()
    if not user:
        return _json_error("Unauthorized", 401)

    fid = _to_uuid(farmer_id)
    if not fid:
        return _json_error("Invalid farmer_id", 400)

    # Only admin or the same farmer can view
    if user.role != ROLE_ADMIN and user.id != fid:
        return _json_error("Forbidden", 403)

    farmer_user = db.session.get(User, fid)  # type: ignore[attr-defined]
    if not farmer_user:
        return _json_error("Farmer not found", 404)

    payload: Dict[str, Any] = {
        "id": str(farmer_user.id),
        "full_name": farmer_user.full_name,
        "email": farmer_user.email,
        "phone": farmer_user.phone,
        "location": farmer_user.location,
        "role": farmer_user.role,
        "farmer_profile": None,
    }

    if FarmerModel is not None:
        try:
            user_id_col = getattr(FarmerModel, "user_id")
            prof = db.session.execute(  # type: ignore[attr-defined]
                select(FarmerModel).where(user_id_col == farmer_user.id)
            ).scalar_one_or_none()
            payload["farmer_profile"] = prof.to_dict() if prof else None
        except Exception:
            payload["farmer_profile"] = None

    return jsonify({"success": True, "farmer": payload})


# ----------------------------------------------------------------------------
# GET /overview  (Frontend master endpoint)
# ----------------------------------------------------------------------------
@farmers_bp.get("/overview", strict_slashes=False)
@token_required
def farmer_overview() -> Any:
    """
    Frontend FarmerDashboard expects (main fields):
      product_count, orders_received_count, revenue_paid_total,
      avg_rating, feedback_count, farmer_rank, low_stock_count,
      revenue_by_day, recent_orders, top_products
    """
    user = _current_user()
    if not user:
        return _json_error("Unauthorized", 401)

    # Admin can request overview for any farmer via ?farmerId=
    requested = _to_uuid(request.args.get("farmerId") or request.args.get("farmer_id") or request.args.get("id"))

    if user.role == ROLE_ADMIN and requested:
        target_farmer_id = requested
    else:
        if user.role not in (ROLE_FARMER, ROLE_ADMIN):
            return _json_error("Farmer access required", 403)
        target_farmer_id = user.id

    days = max(1, min(_to_int(request.args.get("days"), 7), 365))
    q = (request.args.get("q") or "").strip()
    low_stock_threshold = _to_decimal(request.args.get("low_stock_threshold"), Decimal("5"))

    since = _utc_now_naive() - timedelta(days=days)

    # ------------------------------------------------------------
    # Products KPIs
    # ------------------------------------------------------------
    active_statuses = ("available", "approved", "active", "published")

    product_count = (
        db.session.query(func.count(Product.id))  # type: ignore[attr-defined]
        .filter(Product.farmer_id == target_farmer_id)
        .filter(or_(Product.status.is_(None), Product.status.in_(active_statuses)))
        .scalar()
        or 0
    )

    low_stock_count = (
        db.session.query(func.count(Product.id))  # type: ignore[attr-defined]
        .filter(Product.farmer_id == target_farmer_id)
        .filter(Product.quantity <= low_stock_threshold)
        .scalar()
        or 0
    )

    # ------------------------------------------------------------
    # Orders aggregation (multi-item)
    #   orders_received_count: DISTINCT orders containing farmer products
    #   revenue_paid_total: sum of farmer line_totals for paid orders
    # ------------------------------------------------------------
    orders_received_count = (
        db.session.query(func.count(func.distinct(Order.id)))  # type: ignore[attr-defined]
        .select_from(Order)
        .join(OrderItem, OrderItem.order_id == Order.id)
        .join(Product, Product.id == OrderItem.product_id)
        .filter(Product.farmer_id == target_farmer_id)
        .filter(Order.order_date >= since)
        .scalar()
        or 0
    )

    paid_revenue_row = (
        db.session.query(func.sum(OrderItem.line_total))  # type: ignore[attr-defined]
        .select_from(Order)
        .join(OrderItem, OrderItem.order_id == Order.id)
        .join(Product, Product.id == OrderItem.product_id)
        .filter(Product.farmer_id == target_farmer_id)
        .filter(Order.order_date >= since)
        .filter(func.lower(func.coalesce(Order.payment_status, "")) == "paid")
        .first()
    )
    revenue_paid_total = _safe_float(paid_revenue_row[0] if paid_revenue_row else 0)

    # ------------------------------------------------------------
    # Revenue trend by day (paid only; farmer subtotal)
    # NOTE: use Date() instance to satisfy type stubs
    # ------------------------------------------------------------
    day_expr = sa_cast(Order.order_date, Date())
    rows_by_day: List[Tuple[date, Any]] = (
        db.session.query(  # type: ignore[attr-defined]
            day_expr.label("day"),
            func.sum(OrderItem.line_total).label("rev"),
        )
        .select_from(Order)
        .join(OrderItem, OrderItem.order_id == Order.id)
        .join(Product, Product.id == OrderItem.product_id)
        .filter(Product.farmer_id == target_farmer_id)
        .filter(Order.order_date >= since)
        .filter(func.lower(func.coalesce(Order.payment_status, "")) == "paid")
        .group_by(day_expr)
        .order_by(day_expr)
        .all()
    )

    # Fill missing days for smooth charts
    rev_map: Dict[str, float] = {d.isoformat(): _safe_float(v) for d, v in rows_by_day}
    series: List[Dict[str, Any]] = []
    for i in range(days):
        d = (date.today() - timedelta(days=(days - 1 - i))).isoformat()
        series.append({"date": d, "value": round(rev_map.get(d, 0.0), 2)})

    # ------------------------------------------------------------
    # Recent orders list (farmer subtotal per order)
    # Optional query filter applies here (q)
    # ------------------------------------------------------------
    like = f"%{q.lower()}%"

    recent_q = (
        db.session.query(  # type: ignore[attr-defined]
            Order.id.label("order_id"),
            Order.order_date.label("order_date"),
            Order.status.label("status"),
            Order.payment_status.label("payment_status"),
            User.full_name.label("buyer_name"),
            func.sum(OrderItem.line_total).label("farmer_total"),
        )
        .select_from(Order)
        .join(User, User.id == Order.buyer_id)
        .join(OrderItem, OrderItem.order_id == Order.id)
        .join(Product, Product.id == OrderItem.product_id)
        .filter(Product.farmer_id == target_farmer_id)
        .filter(Order.order_date >= since)
        .group_by(Order.id, Order.order_date, Order.status, Order.payment_status, User.full_name)
        .order_by(desc(Order.order_date))
        .limit(12)
    )

    if q:
        recent_q = recent_q.filter(
            or_(
                func.lower(func.coalesce(User.full_name, "")).like(like),
                func.lower(func.coalesce(Product.product_name, "")).like(like),
                func.lower(func.coalesce(Order.status, "")).like(like),
                func.lower(func.coalesce(Order.payment_status, "")).like(like),
                # FIX: db.String is not a type engine → use String()
                func.lower(sa_cast(Order.id, String())).like(like),
            )
        )

    recent_rows = recent_q.all()

    recent_orders: List[Dict[str, Any]] = []
    for oid, odt, status, pstatus, buyer_name, farmer_total in recent_rows:
        recent_orders.append(
            {
                "order_id": str(oid),
                "id": str(oid),  # alias used by some UIs
                "order_date": odt.isoformat() if odt else None,
                "status": status,
                "payment_status": pstatus,
                "buyer_name": buyer_name or "Buyer",
                "total": round(_safe_float(farmer_total), 2),  # farmer subtotal
            }
        )

    # ------------------------------------------------------------
    # Top products (most ordered in range)
    # "orders" is count of DISTINCT orders containing that product.
    # ------------------------------------------------------------
    top_rows = (
        db.session.query(  # type: ignore[attr-defined]
            Product.id.label("product_id"),
            Product.product_name.label("name"),
            Product.quantity.label("stock"),
            func.count(func.distinct(Order.id)).label("orders"),
        )
        .select_from(Product)
        .join(OrderItem, OrderItem.product_id == Product.id)
        .join(Order, Order.id == OrderItem.order_id)
        .filter(Product.farmer_id == target_farmer_id)
        .filter(Order.order_date >= since)
        .group_by(Product.id, Product.product_name, Product.quantity)
        .order_by(desc(func.count(func.distinct(Order.id))))
        .limit(8)
        .all()
    )

    top_products: List[Dict[str, Any]] = [
        {
            "product_id": str(pid),
            "name": str(name or "Product"),
            "orders": int(o or 0),
            "stock": round(_safe_float(stock), 3),
        }
        for pid, name, stock, o in top_rows
    ]

    # ------------------------------------------------------------
    # Ratings window (optional-safe)
    # FIX: avoid RatingModel.rating_id (may not exist in ORM typing)
    # ------------------------------------------------------------
    avg_rating = 0.0
    feedback_count = 0

    if RatingModel is not None:
        try:
            r = (
                db.session.query(  # type: ignore[attr-defined]
                    func.avg(getattr(RatingModel, "rating_score")).label("avg"),
                    func.count().label("n"),
                )
                .select_from(RatingModel)
                .join(Product, Product.id == getattr(RatingModel, "product_id"))
                .filter(Product.farmer_id == target_farmer_id)
                .filter(getattr(RatingModel, "created_at") >= since)
                .first()
            )
            if r:
                avg_rating = round(_safe_float(r[0]), 2)
                feedback_count = int(r[1] or 0)
        except Exception:
            avg_rating = 0.0
            feedback_count = 0

    # ------------------------------------------------------------
    # Farmer rank (explainable rank by avg rating in window)
    # ------------------------------------------------------------
    farmer_rank_label = "—"
    if RatingModel is not None:
        try:
            rank_rows = (
                db.session.query(  # type: ignore[attr-defined]
                    Product.farmer_id.label("farmer_id"),
                    func.avg(getattr(RatingModel, "rating_score")).label("avg"),
                    func.count().label("n"),
                )
                .select_from(Product)
                .join(RatingModel, getattr(RatingModel, "product_id") == Product.id)
                .filter(getattr(RatingModel, "created_at") >= since)
                .group_by(Product.farmer_id)
                .order_by(desc(func.avg(getattr(RatingModel, "rating_score"))), desc(func.count()))
                .all()
            )

            for idx, row in enumerate(rank_rows, start=1):
                fid = row[0]
                avg = row[1]
                if str(fid) == str(target_farmer_id):
                    farmer_rank_label = f"#{idx} • {round(_safe_float(avg), 1)}"
                    break
        except Exception:
            farmer_rank_label = "—"

    # ------------------------------------------------------------
    # Response (frontend-friendly + backward aliases)
    # ------------------------------------------------------------
    payload = {
        "success": True,
        "farmer_id": str(target_farmer_id),
        "days": days,
        "q": q,

        # ✅ Frontend expected fields
        "product_count": int(product_count),
        "orders_received_count": int(orders_received_count),
        "revenue_paid_total": round(float(revenue_paid_total), 2),
        "avg_rating": round(float(avg_rating), 2),
        "feedback_count": int(feedback_count),
        "farmer_rank": farmer_rank_label,
        "low_stock_count": int(low_stock_count),
        "revenue_by_day": series,
        "recent_orders": recent_orders,
        "top_products": top_products,

        # Optional legacy wrapper
        "kpis": {
            "product_count": int(product_count),
            "orders_received_count": int(orders_received_count),
            "revenue_paid_total": round(float(revenue_paid_total), 2),
            "avg_rating": round(float(avg_rating), 2),
            "feedback_count": int(feedback_count),
            "farmer_rank": farmer_rank_label,
            "low_stock_count": int(low_stock_count),
        },
    }

    return jsonify(payload)
