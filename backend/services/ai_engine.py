# ====================================================================
# backend/services/ai_engine.py — Internal Analytics Engine (C1 + Multi-item)
# ====================================================================
# FILE ROLE:
#   Read-only analytics queries over ORM models (NO ML logic).
#   Safe to call from routes/services (empty-safe + null-safe).
#
# WHY THIS FILE IS UPDATED:
#   1) Multi-item schema:
#        Product linkage is in order_items, not orders.
#        Analytics must join:
#          products <- order_items -> orders
#
#   2) FIX FOR YOUR CURRENT ERROR:
#        A Python @property (e.g., Product.name) was being treated like a SQL column.
#        SQLAlchemy expressions REQUIRE mapped columns (InstrumentedAttribute),
#        not Python properties.
#
#   This file now uses ONLY mapped columns:
#     ✅ Product.product_name (mapped column)
#     ✅ Order.order_date     (mapped column)
#     ✅ MarketTrend.timestamp(mapped column)
# ====================================================================

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import desc, func

from backend.database.db import db
from backend.models.market_trend import MarketTrend
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import User

try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def utc_now() -> datetime:
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _safe_str(value: Any) -> str:
    return str(value) if value is not None else ""


def _to_uuid(value: Any) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except Exception:
        return None


# --------------------------------------------------------------------
# Analytics
# --------------------------------------------------------------------
def forecast_product_demand(months: int = 6) -> List[Dict[str, Any]]:
    """
    Naive demand proxy based on order volume over the last N months.

    Multi-item logic:
      Counts DISTINCT orders that included each product.
    """
    months_i = max(int(months), 1)
    since = utc_now() - timedelta(days=30 * months_i)

    # ✅ IMPORTANT: use mapped columns only (no Product.name property)
    rows = (
        db.session.query(  # type: ignore[attr-defined]
            Product.id.label("product_id"),
            Product.product_name.label("product_name"),
            func.count(func.distinct(Order.id)).label("order_count"),
        )
        .select_from(Product)
        .join(OrderItem, OrderItem.product_id == Product.id)
        .join(Order, Order.id == OrderItem.order_id)
        .filter(Order.order_date >= since)
        .group_by(Product.id, Product.product_name)
        .all()
    )

    if not rows:
        return []

    out: List[Dict[str, Any]] = []
    for pid, name, count in rows:
        c = int(count or 0)
        out.append(
            {
                "product_id": _safe_str(pid),
                "product_name": _safe_str(name),
                "forecast_demand_index": min(c * 10, 100),
            }
        )
    return out


def recommend_market_price(product_id: str) -> Dict[str, Any]:
    """
    Recommend price based on the most recent MarketTrend row.

    NOTE:
      MarketTrend.product_id is typically UUID in DB.
      We accept both UUID-string and raw UUID.
    """
    pid = _to_uuid(product_id)
    if not pid:
        # Fall back to string compare only if your MarketTrend.product_id is TEXT (rare).
        trend: Optional[MarketTrend] = (
            db.session.query(MarketTrend)  # type: ignore[attr-defined]
            .filter(MarketTrend.product_id == product_id)  # type: ignore[comparison-overlap]
            .order_by(desc(MarketTrend.timestamp))
            .first()
        )
    else:
        trend = (
            db.session.query(MarketTrend)  # type: ignore[attr-defined]
            .filter(MarketTrend.product_id == pid)
            .order_by(desc(MarketTrend.timestamp))
            .first()
        )

    if not trend:
        return {"product_id": product_id, "message": "No market data"}

    demand_index = int(trend.demand_index or 0)
    multiplier = Decimal("1.0") + (Decimal(demand_index) / Decimal("100.0"))

    avg_price = Decimal(trend.avg_price or 0)
    recommended = (avg_price * multiplier).quantize(Decimal("0.01"))

    return {
        "product_id": product_id,
        "avg_market_price": float(avg_price),
        "demand_index": demand_index,
        "recommended_price": float(recommended),
        "timestamp": trend.timestamp.isoformat() if getattr(trend, "timestamp", None) else None,
    }


def rank_farmers_by_rating() -> List[Dict[str, Any]]:
    """
    Rank farmers by average rating across their products.

    Backward alias:
      fulfilled_orders = rating_count
      (older UI sometimes mislabeled this KPI)
    """
    if Rating is None:
        return []

    # ✅ IMPORTANT: only mapped columns in SQL expressions
    rows = (
        db.session.query(  # type: ignore[attr-defined]
            Product.farmer_id.label("farmer_id"),
            func.avg(Rating.rating_score).label("avg_rating"),
            func.count(Rating.id).label("rating_count"),
        )
        .outerjoin(Rating, Rating.product_id == Product.id)
        .group_by(Product.farmer_id)
        .all()
    )

    if not rows:
        return []

    out: List[Dict[str, Any]] = []
    for fid, avg, cnt in rows:
        avg_f = float(avg or 0.0)
        cnt_i = int(cnt or 0)
        out.append(
            {
                "farmer_id": _safe_str(fid),
                "avg_rating": round(avg_f, 2),
                "rating_count": cnt_i,
                "fulfilled_orders": cnt_i,  # backward alias
            }
        )
    return out


def average_purchases_by_location() -> List[Dict[str, Any]]:
    """
    Aggregated order counts by customer location (anonymized).

    Counts total orders placed by users in each location.
    """
    rows = (
        db.session.query(  # type: ignore[attr-defined]
            User.location.label("location"),
            func.count(Order.id).label("total_orders"),
        )
        .outerjoin(Order, Order.buyer_id == User.id)
        .group_by(User.location)
        .all()
    )

    if not rows:
        return []

    return [{"location": (loc or "Unknown"), "total_orders": int(count or 0)} for loc, count in rows]
