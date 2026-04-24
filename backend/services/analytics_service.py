# ============================================================================
# backend/services/analytics_service.py — Analytics Aggregation Layer (C1 + Multi-item)
# ============================================================================
# FILE ROLE:
#   Read-only analytics aggregation for dashboards + AI inputs.
#   Returns JSON-serializable dicts/lists (NO ORM objects).
#
# WHY THIS VERSION EXISTS:
#   ✅ Fixes the farmer-ranking / weekly-top-farmers 500 errors
#   ✅ Uses typing.cast for Python typing
#   ✅ Uses SQLAlchemy cast as sa_cast only for SQL expressions
#   ✅ Keeps order timestamp handling robust across model aliases
# ============================================================================

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, cast

from sqlalchemy import DateTime, cast as sa_cast, func, select
from sqlalchemy.sql.elements import ColumnElement

from backend.database.db import db
from backend.models import Product, User
from backend.models.order import Order
from backend.models.order_item import OrderItem

try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]


def utc_now_naive() -> datetime:
    """
    Keep analytics window timestamps naive because orders.order_date in the
    current database is timestamp without time zone.
    """
    return datetime.utcnow()


def _order_timestamp_column() -> ColumnElement[Any]:
    """
    Resolve an Order timestamp column robustly.

    CRITICAL FIX:
    The previous version accidentally called SQLAlchemy cast(...) here instead
    of typing.cast(...), which caused the runtime 500 on Order.order_date.
    """
    for name in ("order_date", "created_at", "created_on"):
        col = getattr(Order, name, None)
        if col is not None:
            return cast(ColumnElement[Any], col)
    raise RuntimeError("Order model must define order_date/created_at/created_on.")


def get_ranking_inputs(window_days: int = 30, top_n: int = 10) -> Dict[str, Any]:
    """
    Aggregated product performance inputs for AI ranking.

    Output:
      { window_days, products:[{product_id, product_name, avg_rating, total_orders}] }

    Notes:
      • total_orders = count DISTINCT orders containing the product in window
      • avg_rating   = average rating score (windowed if ratings exist)
    """
    window_days = max(int(window_days), 1)
    top_n = max(int(top_n), 1)

    since = utc_now_naive() - timedelta(days=window_days)
    order_ts = _order_timestamp_column()

    q = (
        db.session.query(  # type: ignore[attr-defined]
            Product.id.label("product_id"),
            Product.product_name.label("product_name"),
            func.count(func.distinct(Order.id)).label("total_orders"),
        )
        .outerjoin(OrderItem, OrderItem.product_id == Product.id)
        .outerjoin(Order, Order.id == OrderItem.order_id)
        .filter(sa_cast(order_ts, DateTime(timezone=False)) >= since)
        .group_by(Product.id, Product.product_name)
        .order_by(func.count(func.distinct(Order.id)).desc())
        .limit(top_n)
    )

    rows = q.all()

    avg_map: Dict[str, float] = {}
    if Rating is not None and rows:
        pids = [pid for (pid, _, _) in rows]
        rrows = (
            db.session.query(  # type: ignore[attr-defined]
                Rating.product_id,
                func.avg(Rating.rating_score).label("avg"),
            )
            .filter(Rating.product_id.in_(pids))  # type: ignore[arg-type]
            .filter(Rating.created_at >= since)
            .group_by(Rating.product_id)
            .all()
        )
        avg_map = {str(pid): float(avg or 0.0) for pid, avg in rrows}

    return {
        "window_days": window_days,
        "products": [
            {
                "product_id": str(pid),
                "product_name": str(name),
                "avg_rating": round(float(avg_map.get(str(pid), 0.0)), 2),
                "total_orders": int(total or 0),
            }
            for pid, name, total in rows
        ],
    }


def get_stock_alert_inputs(farmer_id: Optional[str], days: int = 7) -> List[Dict[str, Any]]:
    """
    Provide stock + recent-order counts per product for a farmer.

    recent_orders = count DISTINCT orders containing that product (last N days)
    """
    days = max(int(days), 1)
    since = utc_now_naive() - timedelta(days=days)
    order_ts = _order_timestamp_column()

    stmt = (
        select(
            Product.id.label("product_id"),
            Product.quantity.label("available_stock"),
            func.count(func.distinct(Order.id)).label("recent_orders"),
        )
        .select_from(Product)
        .outerjoin(OrderItem, OrderItem.product_id == Product.id)
        .outerjoin(Order, Order.id == OrderItem.order_id)
        .where(sa_cast(order_ts, DateTime(timezone=False)) >= since)
        .group_by(Product.id, Product.quantity)
    )

    if farmer_id:
        stmt = stmt.where(Product.farmer_id == farmer_id)

    rows = db.session.execute(stmt).all()  # type: ignore[attr-defined]

    return [
        {
            "product_id": str(pid),
            "available_stock": float(stock or 0),
            "recent_orders": int(rcount or 0),
        }
        for pid, stock, rcount in rows
    ]


def average_purchases_by_location() -> List[Dict[str, Any]]:
    """Count orders by customer location (anonymized)."""
    rows = (
        db.session.query(  # type: ignore[attr-defined]
            User.location.label("location"),
            func.count(Order.id).label("orders"),
        )
        .join(Order, Order.buyer_id == User.id)
        .group_by(User.location)
        .all()
    )

    return [{"location": (loc or "Unknown"), "total_orders": int(count or 0)} for loc, count in rows]