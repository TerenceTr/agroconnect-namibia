# ============================================================================
# backend/routes/ai_analytics.py — AI Gateway + Dashboard Analytics
# ============================================================================
# FILE ROLE:
#   • AI gateway endpoints used by dashboards
#   • Admin AI analytics endpoints used by admin widgets:
#       GET /api/ai/analytics/model-accuracy
#       GET /api/ai/analytics/sales-by-category
#
# FARMER ANALYTICS ENDPOINTS:
#   • GET /api/ai/market-trends?farmer_id=<uuid>&days=30
#       -> chart-ready { series:[{date,demand_index,confidence,...}] }
#   • GET /api/ai/trends (alias of market-trends)
#   • GET /api/ai/stock-alerts?farmer_id=<uuid>&days=30
#       -> list { alerts:[...] } joined to farmer products
#
# RANKING ENDPOINTS:
#   • GET /api/ai/farmer-ranking?farmer_id=<uuid>&days=60&top_percent_target=17
#       -> best-effort rank out of all farmers using orders + revenue
#   • GET /api/ai/weekly-top-farmers?days=7&limit=3
#       -> rolling-window top N farmers (default top 3)
#
# IMPORTANT:
#   ✅ No synthetic/estimated fallback rows for market trends/stock alerts.
#      Endpoints return DB-backed rows only; empty datasets are returned as [].
#   ✅ Schema-robust field resolution for Product/MarketTrend/AIStockAlert models.
#   ✅ FIX: MarketTrend.timestamp is now supported, so real trend rows can render.
#   ✅ FIX: Stock alerts now expose richer fields for stronger farmer UX:
#        - alert_id
#        - current_stock / available_stock
#        - forecast_demand / demand_forecast / predicted_demand
#        - recommended_restock
#        - category / unit / severity / model_version
#   ✅ FIX: Farmer ranking now prefers direct DB aggregation from:
#        orders + order_items + products + payments + users
#        then falls back to analytics payloads only if needed.
#   ✅ FIX: Weekly top farmers now supports rolling windows (7, 30, 90, 365 days).
#
# PYRIGHT FIX:
#   ✅ Do NOT type SQLAlchemy query builders as Sequence[...] before execution.
#      Sequence is the RESULT type after `.all()`, not the query object type.
# ============================================================================

from __future__ import annotations

import math
from datetime import date, datetime, timedelta
from decimal import Decimal
from typing import Any, Dict, List, Optional, Sequence, Tuple

from flask.blueprints import Blueprint
from flask.globals import current_app, request
from flask.json import jsonify

from sqlalchemy import case, func, literal, or_

from backend.database.db import db
from backend.security import admin_required, token_required

from backend.models.product import Product
from backend.models.market_trend import MarketTrend
from backend.models.ai_stock_alert import AIStockAlert
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.payment import Payment
from backend.models.user import User

from backend.services.ai_engine import (
    average_purchases_by_location,
    forecast_product_demand,
    rank_farmers_by_rating,
    recommend_market_price,
)
from backend.services.analytics_service import get_ranking_inputs, get_stock_alert_inputs
from backend.services.ai_analytics_service import (
    get_model_accuracy_series,
    get_sales_by_category,
)

ai_bp = Blueprint("ai", __name__)


# --------------------------------------------------------------------
# Generic helpers
# --------------------------------------------------------------------
def _safe_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s if s else None
    s = str(v).strip()
    return s if s else None


def _to_float(v: Any, default: float = 0.0) -> float:
    if v is None:
        return default
    try:
        if isinstance(v, Decimal):
            return float(v)
        return float(v)
    except Exception:
        return default


def _cfg_bool(name: str, default: bool) -> bool:
    """
    Robust boolean config reader for settings-driven AI feature toggles.
    """
    value = current_app.config.get(name, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _get_attr(obj: Any, *names: str) -> Any:
    """
    Schema-robust attribute reader.

    This allows the same route code to work even if model fields differ slightly
    across environments, migrations, or naming conventions.
    """
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def _parse_int_arg(name: str, default: int, *, min_value: int, max_value: int) -> int:
    raw = request.args.get(name)
    try:
        val = int(raw) if raw is not None else default
    except Exception:
        val = default
    return max(min_value, min(max_value, val))


def _parse_int_arg_multi(
    names: Sequence[str],
    default: int,
    *,
    min_value: int,
    max_value: int,
) -> int:
    raw: Optional[str] = None
    for n in names:
        got = request.args.get(n)
        if got is not None and str(got).strip() != "":
            raw = got
            break

    try:
        val = int(raw) if raw is not None else default
    except Exception:
        val = default
    return max(min_value, min(max_value, val))


def _parse_farmer_id() -> Optional[str]:
    """
    Accept both snake_case and camelCase for frontend compatibility.
    """
    return _safe_str(request.args.get("farmer_id") or request.args.get("farmerId"))


def _product_join_expr():
    """
    Resolve Product PK for joins:
      - products.product_id
      - products.id
    """
    return getattr(Product, "product_id", None) or getattr(Product, "id", None)


def _product_owner_expr():
    """
    Resolve Product owner column:
      - products.user_id
      - products.farmer_id
    """
    return getattr(Product, "user_id", None) or getattr(Product, "farmer_id", None)


def _trend_observed_expr():
    """
    Resolve trend timestamp/date column across schema variants.

    IMPORTANT FIX:
      MarketTrend in this project may use `timestamp`.
      If it is not included here, the market-trends endpoint can return no
      usable series rows even when the table has data.
    """
    return (
        getattr(MarketTrend, "observed_at", None)
        or getattr(MarketTrend, "created_at", None)
        or getattr(MarketTrend, "computed_at", None)
        or getattr(MarketTrend, "trend_date", None)
        or getattr(MarketTrend, "date", None)
        or getattr(MarketTrend, "timestamp", None)
    )


def _trend_demand_value(row: MarketTrend) -> float:
    return _to_float(
        _get_attr(
            row,
            "demand_index",
            "predicted_demand",
            "demand_forecast",
            "demand_score",
            "value",
        ),
        0.0,
    )


def _trend_confidence_value(row: MarketTrend) -> float:
    return _to_float(
        _get_attr(row, "confidence", "confidence_score", "model_confidence"),
        0.0,
    )


def _trend_avg_price_value(row: MarketTrend) -> float:
    """
    Optional trend-side price metric for richer charting/insight panels.
    Safe to expose even if frontend does not use it yet.
    """
    return _to_float(
        _get_attr(
            row,
            "avg_price",
            "average_price",
            "recommended_price",
            "market_price",
            "price",
        ),
        0.0,
    )


def _alert_time_expr():
    """
    Resolve stock-alert timestamp column across schema variants.
    """
    return (
        getattr(AIStockAlert, "computed_at", None)
        or getattr(AIStockAlert, "created_at", None)
        or getattr(AIStockAlert, "alerted_at", None)
        or getattr(AIStockAlert, "timestamp", None)
        or getattr(AIStockAlert, "date", None)
    )


def _iso_date(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.date().isoformat()
    if isinstance(v, date):
        return v.isoformat()
    try:
        return str(v)[:10]
    except Exception:
        return None


def _iso_datetime(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, date):
        return datetime.combine(v, datetime.min.time()).isoformat()
    return _safe_str(v)


def _unwrap_api_envelope(raw: Any) -> Any:
    """
    Envelope-safe unwrapping:
      - { ok: true, data: ... }
      - { success: true, data: ... }
      - nested data wrappers
    """
    cur = raw
    guard = 0
    while isinstance(cur, dict) and "data" in cur and cur.get("data") is not None and guard < 4:
        cur = cur.get("data")
        guard += 1
    return cur


def _extract_rows_from_payload(raw: Any) -> List[Dict[str, Any]]:
    """
    Ranking payload normalizer.

    Accepts arrays or dicts with keys such as:
      rows / ranking / leaderboard / farmers / items / results / data
    """
    payload = _unwrap_api_envelope(raw)

    if isinstance(payload, list):
        return [x for x in payload if isinstance(x, dict)]

    if not isinstance(payload, dict):
        return []

    candidate_keys = (
        "rows",
        "ranking",
        "leaderboard",
        "farmers",
        "items",
        "results",
        "data",
    )
    for key in candidate_keys:
        v = payload.get(key)
        unwrapped = _unwrap_api_envelope(v)
        if isinstance(unwrapped, list):
            return [x for x in unwrapped if isinstance(x, dict)]

    return []


def _norm_int_like(v: Any, default: int = 0) -> int:
    try:
        return int(round(_to_float(v, float(default))))
    except Exception:
        return default


# --------------------------------------------------------------------
# Ranking helpers
# --------------------------------------------------------------------
def _order_pk_expr():
    return getattr(Order, "order_id", None) or getattr(Order, "id", None)


def _order_date_expr():
    return getattr(Order, "order_date", None) or getattr(Order, "created_at", None)


def _order_status_expr():
    return getattr(Order, "status", None)


def _order_item_order_fk_expr():
    return getattr(OrderItem, "order_id", None)


def _order_item_product_fk_expr():
    return getattr(OrderItem, "product_id", None)


def _order_item_qty_expr():
    return getattr(OrderItem, "quantity", None) or getattr(OrderItem, "qty", None)


def _order_item_line_total_expr():
    return getattr(OrderItem, "line_total", None) or getattr(OrderItem, "total", None)


def _payment_order_fk_expr():
    return getattr(Payment, "order_id", None)


def _payment_status_expr():
    return getattr(Payment, "status", None)


def _user_pk_expr():
    return getattr(User, "id", None) or getattr(User, "user_id", None)


def _user_name_expr():
    return (
        getattr(User, "full_name", None)
        or getattr(User, "name", None)
        or getattr(User, "display_name", None)
        or getattr(User, "username", None)
    )


def _user_location_expr():
    return (
        getattr(User, "location", None)
        or getattr(User, "town", None)
        or getattr(User, "city", None)
        or getattr(User, "region", None)
    )


def _build_paid_orders_subquery():
    """
    One-row-per-order paid flag.
    Prevents duplicate revenue inflation when an order has multiple payment rows.
    """
    payment_order_fk = _payment_order_fk_expr()
    payment_status = _payment_status_expr()

    if payment_order_fk is None or payment_status is None:
        return None

    return (
        db.session.query(
            payment_order_fk.label("order_id"),
            func.max(
                case(
                    (func.lower(payment_status) == "paid", 1),
                    else_=0,
                )
            ).label("has_paid"),
        )
        .group_by(payment_order_fk)
        .subquery()
    )


def _query_farmer_orders_revenue_rows(
    window_days: int,
    *,
    candidate_limit: int = 5000,
) -> List[Dict[str, Any]]:
    """
    Market-wide farmer aggregates.

    Ranking basis:
      1) distinct paid/completed orders containing the farmer's products
      2) revenue from order_items.line_total
      3) total quantity sold

    Output row shape:
      {
        farmer_id,
        farmer_name,
        farmer_location,
        orders_count,
        revenue_total,
        qty_total
      }
    """
    since = datetime.utcnow() - timedelta(days=max(1, int(window_days)))

    product_pk = _product_join_expr()
    product_owner = _product_owner_expr()
    order_pk = _order_pk_expr()
    order_date = _order_date_expr()
    order_status = _order_status_expr()
    order_item_order_fk = _order_item_order_fk_expr()
    order_item_product_fk = _order_item_product_fk_expr()
    qty_col = _order_item_qty_expr()
    line_total_col = _order_item_line_total_expr()
    user_pk = _user_pk_expr()
    user_name = _user_name_expr()
    user_location = _user_location_expr()

    if (
        product_pk is None
        or product_owner is None
        or order_pk is None
        or order_date is None
        or order_item_order_fk is None
        or order_item_product_fk is None
        or qty_col is None
        or line_total_col is None
        or user_pk is None
    ):
        return []

    farmer_name_expr = (
        user_name.label("farmer_name")
        if user_name is not None
        else product_owner.label("farmer_name")
    )
    farmer_location_expr = (
        user_location.label("farmer_location")
        if user_location is not None
        else literal("").label("farmer_location")
    )

    paid_orders_sq = _build_paid_orders_subquery()

    q: Any = (
        db.session.query(
            product_owner.label("farmer_id"),
            farmer_name_expr,
            farmer_location_expr,
            func.count(func.distinct(order_pk)).label("orders_count"),
            func.coalesce(func.sum(line_total_col), 0).label("revenue_total"),
            func.coalesce(func.sum(qty_col), 0).label("qty_total"),
        )
        .select_from(OrderItem)
        .join(Product, product_pk == order_item_product_fk)
        .join(Order, order_pk == order_item_order_fk)
        .outerjoin(User, user_pk == product_owner)
        .filter(order_date >= since)
    )

    # Paid orders are preferred. If payment rows are not available, completed orders still count.
    if paid_orders_sq is not None:
        q = q.outerjoin(paid_orders_sq, paid_orders_sq.c.order_id == order_pk)
        if order_status is not None:
            q = q.filter(
                or_(
                    paid_orders_sq.c.has_paid == 1,
                    func.lower(order_status) == "completed",
                )
            )
        else:
            q = q.filter(paid_orders_sq.c.has_paid == 1)
    else:
        if order_status is None:
            return []
        q = q.filter(func.lower(order_status) == "completed")

    q = (
        q.group_by(product_owner, farmer_name_expr, farmer_location_expr)
        .order_by(
            func.coalesce(func.sum(line_total_col), 0).desc(),
            func.count(func.distinct(order_pk)).desc(),
            func.coalesce(func.sum(qty_col), 0).desc(),
        )
        .limit(candidate_limit)
    )

    rows = q.all()

    out: List[Dict[str, Any]] = []
    for row in rows:
        farmer_id = _safe_str(getattr(row, "farmer_id", None))
        farmer_name = _safe_str(getattr(row, "farmer_name", None)) or "Farmer"
        farmer_location = _safe_str(getattr(row, "farmer_location", None)) or "Location not set"

        out.append(
            {
                "farmer_id": farmer_id or f"farmer:{farmer_name.lower()}",
                "farmer_name": farmer_name,
                "farmer_location": farmer_location,
                "orders_count": _norm_int_like(getattr(row, "orders_count", 0)),
                "revenue_total": max(0.0, _to_float(getattr(row, "revenue_total", 0.0))),
                "qty_total": max(0.0, _to_float(getattr(row, "qty_total", 0.0))),
            }
        )

    return out


def _normalize_rank_row(raw: Dict[str, Any], fallback_idx: int) -> Dict[str, Any]:
    farmer_id = _safe_str(
        raw.get("farmer_id")
        or raw.get("user_id")
        or raw.get("id")
        or raw.get("farmerId")
        or raw.get("userId")
    )

    farmer_name = _safe_str(
        raw.get("farmer_name")
        or raw.get("name")
        or raw.get("display_name")
        or raw.get("username")
        or raw.get("label")
    ) or "Farmer"

    farmer_location = _safe_str(
        raw.get("farmer_location")
        or raw.get("location")
        or raw.get("farmerLocation")
        or raw.get("town")
        or raw.get("city")
        or raw.get("region")
    ) or "Location not set"

    orders_count = _norm_int_like(
        raw.get("orders_count")
        or raw.get("order_count")
        or raw.get("orders")
        or raw.get("total_orders")
        or raw.get("count_orders")
    )

    revenue_total = _to_float(
        raw.get("revenue_total")
        or raw.get("revenue")
        or raw.get("sales_total")
        or raw.get("sales")
        or raw.get("amount")
        or raw.get("total")
        or 0.0,
        0.0,
    )

    qty_total = _to_float(
        raw.get("qty_total")
        or raw.get("quantity_total")
        or raw.get("total_qty")
        or raw.get("total_quantity")
        or raw.get("qty")
        or 0.0,
        0.0,
    )

    safe_fid = farmer_id or f"row:{fallback_idx}:{farmer_name.lower()}"

    return {
        "farmer_id": safe_fid,
        "farmer_name": farmer_name,
        "farmer_location": farmer_location,
        "orders_count": max(0, orders_count),
        "revenue_total": max(0.0, revenue_total),
        "qty_total": max(0.0, qty_total),
    }


def _rank_by_orders_and_revenue(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Composite score ranking:
      score = 0.70 * normalized_revenue + 0.30 * normalized_orders
    """
    if not rows:
        return []

    normalized = [_normalize_rank_row(r, idx) for idx, r in enumerate(rows)]
    max_revenue = max((r["revenue_total"] for r in normalized), default=0.0)
    max_orders = max((r["orders_count"] for r in normalized), default=0)

    ranked_seed: List[Dict[str, Any]] = []
    for r in normalized:
        r_rev = (r["revenue_total"] / max_revenue) if max_revenue > 0 else 0.0
        r_ord = (float(r["orders_count"]) / float(max_orders)) if max_orders > 0 else 0.0
        score = 0.70 * r_rev + 0.30 * r_ord

        ranked_seed.append(
            {
                **r,
                "composite_score": round(score, 6),
            }
        )

    ranked_seed.sort(
        key=lambda x: (
            x["composite_score"],
            x["revenue_total"],
            x["orders_count"],
            x["qty_total"],
            (x["farmer_name"] or "").lower(),
        ),
        reverse=True,
    )

    total = len(ranked_seed)
    ranked: List[Dict[str, Any]] = []
    for i, r in enumerate(ranked_seed, start=1):
        top_percent = max(1, int(math.ceil((i / max(1, total)) * 100.0)))
        ranked.append(
            {
                "rank": i,
                "top_percent": top_percent,
                "top_percent_label": f"Top {top_percent}%",
                "rank_out_of_total_label": f"{i} out of {total} farmers",
                **r,
            }
        )

    return ranked


def _build_orders_revenue_ranking(
    window_days: int,
    *,
    candidate_limit: int = 5000,
) -> List[Dict[str, Any]]:
    """
    Best-effort farmer ranking source strategy:
      1) direct DB aggregation from orders + payments + order_items + products + users
      2) fallback to existing analytics payload
      3) fallback to AI rating ranking
    """
    rows = _query_farmer_orders_revenue_rows(window_days, candidate_limit=candidate_limit)

    if not rows:
        rows = _extract_rows_from_payload(get_ranking_inputs(window_days, candidate_limit))

    if not rows:
        rows = _extract_rows_from_payload(rank_farmers_by_rating())

    return _rank_by_orders_and_revenue(rows)


def _normalize_risk_level(v: Any) -> str:
    """
    Normalize stock-alert severity into a stable frontend-safe scale.
    """
    raw = (_safe_str(v) or "medium").lower()

    if raw in {"critical", "very_high", "very-high"}:
        return "high"
    if raw in {"high", "warning"}:
        return "high"
    if raw in {"medium", "moderate"}:
        return "medium"
    if raw in {"low", "ok", "normal"}:
        return "low"

    return "medium"


@ai_bp.route("/ping", methods=["GET"])
def ping() -> Any:
    return jsonify({"status": "ok", "service": "ai-gateway"})


# --------------------------------------------------------------------
# AI / dashboard support endpoints (existing)
# --------------------------------------------------------------------
@ai_bp.route("/forecast-demand", methods=["GET"])
@token_required
def forecast_demand() -> Any:
    months = _parse_int_arg("months", default=6, min_value=1, max_value=36)
    return jsonify(forecast_product_demand(months))


@ai_bp.route("/recommend-price", methods=["GET"])
@token_required
def recommend_price() -> Any:
    product_id = request.args.get("product_id", "")
    return jsonify(recommend_market_price(product_id))


@ai_bp.route("/rank-farmers", methods=["GET"])
@token_required
def farmer_ranking() -> Any:
    # Backward-compatible legacy endpoint retained.
    return jsonify(rank_farmers_by_rating())


@ai_bp.route("/average-purchases-location", methods=["GET"])
@token_required
def location_stats() -> Any:
    return jsonify(average_purchases_by_location())


@ai_bp.route("/ranking-inputs", methods=["GET"])
@token_required
def ranking_inputs() -> Any:
    window_days = _parse_int_arg_multi(
        ("window_days", "days"),
        default=30,
        min_value=1,
        max_value=1095,
    )
    top_n = _parse_int_arg("top_n", default=10, min_value=1, max_value=5000)
    return jsonify(get_ranking_inputs(window_days, top_n))


@ai_bp.route("/stock-alert-inputs", methods=["GET"])
@token_required
def stock_alert_inputs() -> Any:
    farmer_id = request.args.get("farmer_id")
    days = _parse_int_arg("days", default=7, min_value=1, max_value=1095)
    return jsonify(get_stock_alert_inputs(farmer_id, days))


# --------------------------------------------------------------------
# Farmer-facing analytics endpoints
# --------------------------------------------------------------------
@ai_bp.route("/market-trends", methods=["GET"])
@token_required
def market_trends() -> Any:
    """
    DB-backed chart series only (no synthetic fallback):
      {
        "series": [
          {
            "date": "2026-01-01",
            "demand_index": 72.1,
            "confidence": 0.83,
            "avg_price": 35.4,
            "point_count": 3
          }
        ],
        "days": 30,
        "farmer_id": "<uuid or null>",
        "source": "market_trends"
      }

    IMPORTANT:
      - Uses only persisted MarketTrend rows
      - Aggregates by calendar day
      - Supports timestamp-style schemas
    """
    farmer_id = _parse_farmer_id()
    if not _cfg_bool("MARKET_TRENDS_ENABLED", True):
        return jsonify({
            "series": [],
            "days": _parse_int_arg_multi(("days", "window_days"), default=30, min_value=1, max_value=1095),
            "farmer_id": farmer_id,
            "source": "market_trends",
            "message": "Market trends are disabled in system settings.",
        })

    days = _parse_int_arg_multi(("days", "window_days"), default=30, min_value=1, max_value=1095)
    since = datetime.utcnow() - timedelta(days=days)

    product_pk = _product_join_expr()
    product_owner = _product_owner_expr()
    observed_col = _trend_observed_expr()
    trend_product_fk = getattr(MarketTrend, "product_id", None)

    # Defensive: if core schema pieces are missing, return empty dataset.
    if product_pk is None or observed_col is None or trend_product_fk is None:
        return jsonify(
            {
                "series": [],
                "days": days,
                "farmer_id": farmer_id,
                "source": "market_trends",
                "message": "Demand trends coming soon.",
            }
        )

    q: Any = (
        db.session.query(MarketTrend, Product)
        .join(Product, product_pk == trend_product_fk)
        .filter(observed_col >= since)
    )

    if farmer_id and product_owner is not None:
        q = q.filter(product_owner == farmer_id)

    rows: Sequence[Tuple[MarketTrend, Product]] = (
        q.order_by(observed_col.asc()).limit(10000).all()
    )

    by_day: Dict[str, Dict[str, float]] = {}
    for trend, _product in rows:
        obs = _get_attr(
            trend,
            "observed_at",
            "created_at",
            "computed_at",
            "trend_date",
            "date",
            "timestamp",
        )
        day_key = _iso_date(obs)
        if not day_key:
            continue

        bucket = by_day.setdefault(day_key, {"d_sum": 0.0, "c_sum": 0.0, "p_sum": 0.0, "n": 0.0})
        bucket["d_sum"] += _trend_demand_value(trend)
        bucket["c_sum"] += _trend_confidence_value(trend)
        bucket["p_sum"] += _trend_avg_price_value(trend)
        bucket["n"] += 1.0

    series: List[Dict[str, Any]] = []
    for d in sorted(by_day.keys()):
        b = by_day[d]
        n = b["n"] if b["n"] > 0 else 1.0
        series.append(
            {
                "date": d,
                "demand_index": round(b["d_sum"] / n, 4),
                "confidence": round(b["c_sum"] / n, 4),
                "avg_price": round(b["p_sum"] / n, 2),
                "point_count": int(n),
            }
        )

    payload: Dict[str, Any] = {
        "series": series,
        "days": days,
        "farmer_id": farmer_id,
        "source": "market_trends",
    }
    if not series:
        payload["message"] = "Demand trends coming soon."

    return jsonify(payload)


@ai_bp.route("/trends", methods=["GET"])
@token_required
def trends_alias() -> Any:
    """
    Alias endpoint for frontend convenience.
    Returns the same payload as /market-trends.
    """
    return market_trends()


@ai_bp.route("/stock-alerts", methods=["GET"])
@token_required
def stock_alerts() -> Any:
    """
    DB-backed farmer stock alerts only (no synthetic fallback):
      {
        "alerts": [
          {
            "id": "...",
            "alert_id": "...",
            "product_id": "...",
            "product_name": "...",
            "category": "...",
            "unit": "kg",
            "risk_level": "high",
            "severity": "high",
            "forecast_demand": 23.5,
            "demand_forecast": 23.5,
            "predicted_demand": 23.5,
            "available_stock": 5.0,
            "current_stock": 5.0,
            "recommended_restock": 18.5,
            "recommendation": "...",
            "model_version": "...",
            "computed_at": "ISO",
            "computed_date": "YYYY-MM-DD",
            "acknowledged": false,
            "resolved": false
          }
        ]
      }

    IMPORTANT:
      This richer payload supports more advanced stock-alert UI cards without
      requiring the frontend to guess or synthesize missing metrics.
    """
    farmer_id = _parse_farmer_id()
    if not _cfg_bool("LOW_STOCK_ALERTS_ENABLED", True):
        return jsonify({
            "alerts": [],
            "days": _parse_int_arg_multi(("days", "window_days"), default=30, min_value=1, max_value=1095),
            "farmer_id": farmer_id,
            "source": "ai_stock_alerts",
            "message": "Low-stock alerts are disabled in system settings.",
        })

    days = _parse_int_arg_multi(("days", "window_days"), default=30, min_value=1, max_value=1095)
    limit = _parse_int_arg("limit", default=100, min_value=1, max_value=500)
    since = datetime.utcnow() - timedelta(days=days)

    product_pk = _product_join_expr()
    product_owner = _product_owner_expr()
    alert_time_col = _alert_time_expr()
    alert_product_fk = getattr(AIStockAlert, "product_id", None)

    if product_pk is None or alert_time_col is None or alert_product_fk is None:
        return jsonify(
            {
                "alerts": [],
                "days": days,
                "farmer_id": farmer_id,
                "source": "ai_stock_alerts",
                "message": "No stock alert data available.",
            }
        )

    q: Any = (
        db.session.query(AIStockAlert, Product)
        .join(Product, product_pk == alert_product_fk)
        .filter(alert_time_col >= since)
    )

    if farmer_id and product_owner is not None:
        q = q.filter(product_owner == farmer_id)

    rows: Sequence[Tuple[AIStockAlert, Product]] = (
        q.order_by(alert_time_col.desc()).limit(limit).all()
    )

    out: List[Dict[str, Any]] = []
    for alert, product in rows:
        forecast_demand = _to_float(
            _get_attr(alert, "demand_forecast", "forecast_demand", "predicted_demand"),
            0.0,
        )

        available_stock = _to_float(
            _get_attr(
                alert,
                "available_stock",
                "current_stock",
                "stock_available",
                "stock_on_hand",
            ),
            _to_float(_get_attr(product, "quantity", "stock", "qty", "available_stock"), 0.0),
        )

        recommended_restock = _to_float(
            _get_attr(alert, "recommended_restock", "restock_quantity", "restock_qty"),
            max(0.0, forecast_demand - available_stock),
        )

        risk_level = _normalize_risk_level(
            _get_attr(alert, "risk_level", "alert_level", "severity")
        )

        out.append(
            {
                "id": str(_get_attr(alert, "alert_id", "id") or ""),
                "alert_id": str(_get_attr(alert, "alert_id", "id") or ""),
                "product_id": str(_get_attr(alert, "product_id") or ""),
                "product_name": _safe_str(_get_attr(product, "product_name", "name")) or "Product",
                "category": _safe_str(_get_attr(product, "category", "product_category", "type")),
                "unit": _safe_str(_get_attr(product, "unit", "measure_unit")) or "units",
                "risk_level": risk_level,
                "severity": risk_level,
                "forecast_demand": forecast_demand,
                "demand_forecast": forecast_demand,
                "predicted_demand": forecast_demand,
                "available_stock": available_stock,
                "current_stock": available_stock,
                "recommended_restock": recommended_restock,
                "recommendation": _safe_str(_get_attr(alert, "recommendation", "message", "action")),
                "model_version": _safe_str(_get_attr(alert, "model_version")),
                "computed_at": _iso_datetime(
                    _get_attr(alert, "computed_at", "created_at", "alerted_at", "timestamp")
                ),
                "computed_date": _iso_date(
                    _get_attr(alert, "computed_date", "date", "created_at", "timestamp")
                ),
                "acknowledged": bool(_get_attr(alert, "acknowledged") or False),
                "resolved": bool(_get_attr(alert, "resolved") or False),
            }
        )

    payload: Dict[str, Any] = {
        "alerts": out,
        "days": days,
        "farmer_id": farmer_id,
        "source": "ai_stock_alerts",
    }
    if not out:
        payload["message"] = "No stock alerts found for the selected window."

    return jsonify(payload)


# --------------------------------------------------------------------
# Ranking endpoints
# --------------------------------------------------------------------
@ai_bp.route("/farmer-ranking", methods=["GET"])
@token_required
def farmer_ranking_orders_revenue() -> Any:
    """
    Best-effort farmer ranking by orders + revenue.

    Main display goal:
      - 1 out of 12 farmers
      - Top 9%
    """
    farmer_id = _parse_farmer_id()
    if not _cfg_bool("RANKING_WIDGETS_ENABLED", True):
        return jsonify({
            "basis": "orders_and_revenue",
            "days": _parse_int_arg_multi(("days", "window_days"), default=60, min_value=1, max_value=1095),
            "window_days": _parse_int_arg_multi(("days", "window_days"), default=60, min_value=1, max_value=1095),
            "total_farmers": 0,
            "top_percent_target": _parse_int_arg("top_percent_target", default=17, min_value=1, max_value=100),
            "leaderboard": [],
            "mine": None,
            "message": "Ranking widgets are disabled in system settings.",
        })
    days = _parse_int_arg_multi(("days", "window_days"), default=60, min_value=1, max_value=1095)
    limit = _parse_int_arg("limit", default=10, min_value=1, max_value=100)
    top_percent_target = _parse_int_arg(
        "top_percent_target",
        default=17,
        min_value=1,
        max_value=100,
    )

    ranked = _build_orders_revenue_ranking(days, candidate_limit=5000)
    total = len(ranked)

    mine: Optional[Dict[str, Any]] = None
    if farmer_id:
        mine = next((r for r in ranked if str(r.get("farmer_id")) == str(farmer_id)), None)

    payload: Dict[str, Any] = {
        "basis": "orders_and_revenue",
        "days": days,
        "window_days": days,
        "total_farmers": total,
        "top_percent_target": top_percent_target,
        "leaderboard": ranked[:limit],
        "mine": mine,
    }

    if mine:
        mine_top_percent = int(mine.get("top_percent", 100))
        payload["mine"] = {
            **mine,
            "rank_label": f"#{int(mine.get('rank', 0))} of {total}",
            "rank_out_of_total_label": f"{int(mine.get('rank', 0))} out of {total} farmers",
            "is_top_percent_target": mine_top_percent <= top_percent_target,
            "target_top_percent_label": f"Top {top_percent_target}%",
        }

    if total == 0:
        payload["message"] = "Ranking data coming soon."

    return jsonify(payload)


@ai_bp.route("/weekly-top-farmers", methods=["GET"])
@token_required
def weekly_top_farmers() -> Any:
    """
    Market-wide top farmers for the selected rolling window.

    Although the route name says "weekly", the query supports:
      - 7 days
      - 30 days
      - 90 days
      - up to 365 days
    """
    if not _cfg_bool("RANKING_WIDGETS_ENABLED", True):
        return jsonify({
            "basis": "orders_and_revenue",
            "days": _parse_int_arg_multi(("days", "window_days"), default=7, min_value=1, max_value=365),
            "limit": _parse_int_arg("limit", default=3, min_value=1, max_value=10),
            "top_farmers": [],
            "top_three": [],
            "total_farmers": 0,
            "message": "Ranking widgets are disabled in system settings.",
        })

    limit = _parse_int_arg("limit", default=3, min_value=1, max_value=10)
    days = _parse_int_arg_multi(("days", "window_days"), default=7, min_value=1, max_value=365)

    ranked = _build_orders_revenue_ranking(days, candidate_limit=5000)
    top = ranked[:limit]

    today_utc = datetime.utcnow().date()
    window_start = today_utc - timedelta(days=max(1, days) - 1)

    payload: Dict[str, Any] = {
        "basis": "orders_and_revenue",
        "days": days,
        "limit": limit,
        "window_start": window_start.isoformat(),
        "window_end": today_utc.isoformat(),
        "week_start": window_start.isoformat(),  # backward compatibility
        "week_end": today_utc.isoformat(),       # backward compatibility
        "window_label": f"Last {days} days",
        "top_farmers": top,
        "top_three": top[:3],
        "total_farmers": len(ranked),
    }

    if not top:
        payload["message"] = "Top farmers coming soon."

    return jsonify(payload)


# --------------------------------------------------------------------
# Admin AI analytics endpoints
# --------------------------------------------------------------------
@ai_bp.route("/analytics/model-accuracy", methods=["GET"])
@token_required
@admin_required
def model_accuracy() -> Any:
    """
    Returns chart-ready series:
      { labels:[], accuracy:[], confidence:[] }
    """
    if not _cfg_bool("AI_INSIGHTS_ENABLED", True):
        return jsonify({"labels": [], "values": [], "accuracy": [], "confidence": [], "days": _parse_int_arg_multi(("days", "window_days"), default=30, min_value=1, max_value=1095), "message": "AI analytics insights are disabled in system settings."})

    days = _parse_int_arg_multi(("days", "window_days"), default=30, min_value=1, max_value=1095)
    task = request.args.get("task") or None
    crop = request.args.get("crop") or None
    model_version = request.args.get("model_version") or None

    return jsonify(
        get_model_accuracy_series(
            days=days,
            task=task,
            crop=crop,
            model_version=model_version,
        )
    )


@ai_bp.route("/analytics/sales-by-category", methods=["GET"])
@token_required
@admin_required
def sales_by_category() -> Any:
    """
    Returns:
      { labels:[], values:[], confidence:[] }
    """
    if not _cfg_bool("AI_INSIGHTS_ENABLED", True):
        return jsonify({"labels": [], "values": [], "accuracy": [], "confidence": [], "days": _parse_int_arg_multi(("days", "window_days"), default=30, min_value=1, max_value=1095), "message": "AI analytics insights are disabled in system settings."})

    days = _parse_int_arg_multi(("days", "window_days"), default=30, min_value=1, max_value=1095)
    return jsonify(get_sales_by_category(days=days))