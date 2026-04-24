from __future__ import annotations

# ============================================================================
# backend/routes/customer_insights.py — Customer Commerce Insights API
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Read-only customer analytics + behavior endpoint used by the customer
#   dashboard insights workspace.
#
# WHAT THIS RETURNS:
#   • summary KPIs (orders, spend, paid, delivered, likes, searches)
#   • spend by month
#   • spend by category
#   • top farmers by purchase value
#   • repeat purchases
#   • recent searches
#   • liked products snapshot
#   • payment method mix
#   • customer segmentation intelligence
#   • reorder intelligence
#   • delivery fee share analytics
#   • trust / transparency metrics
#
# DESIGN NOTES:
#   ✅ Uses the current authenticated customer only
#   ✅ Reads from existing marketplace tables already present in the DB
#   ✅ Fails softly when optional analytics tables are empty / unavailable
#   ✅ Keeps payload chart-ready for a modern ecommerce insights page
#   ✅ Batch 5 adds explainable segmentation, reorder, delivery-fee, and trust
#      layers without requiring new tables first
# ============================================================================

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Iterable, Optional

from flask.blueprints import Blueprint
from flask.globals import current_app, request
from flask.json import jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from backend.database.db import db
from backend.utils.require_auth import require_auth

customer_insights_bp = Blueprint("customer_insights", __name__)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _safe_uuid(value: Any) -> Optional[uuid.UUID]:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value).strip())
    except Exception:
        return None


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except Exception:
        return default


def _as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        s = str(value).strip()
    except Exception:
        return default
    return s or default


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    try:
        parsed = datetime.fromisoformat(str(value))
        return parsed.isoformat()
    except Exception:
        return _as_str(value, default="") or None


def _dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except Exception:
        return None


def _pct(numerator: Any, denominator: Any) -> float:
    num = _as_float(numerator, 0.0)
    den = _as_float(denominator, 0.0)
    if den <= 0:
        return 0.0
    return round((num / den) * 100.0, 2)


def _current_user_id() -> Optional[uuid.UUID]:
    user = getattr(request, "current_user", None)
    return _safe_uuid(getattr(user, "id", None) or getattr(user, "user_id", None))


def _current_user_location() -> str:
    user = getattr(request, "current_user", None)
    return _as_str(getattr(user, "location", None), "")


def _run_query(sql: str, params: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    try:
        rows = db.session.execute(text(sql), params or {}).mappings().all()
        return [dict(r) for r in rows]
    except SQLAlchemyError:
        current_app.logger.exception("Customer insights query failed")
        return []


def _first_row(sql: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    rows = _run_query(sql, params)
    return rows[0] if rows else {}


# ---------------------------------------------------------------------------
# Insight builders
# ---------------------------------------------------------------------------
def _build_summary(user_id: uuid.UUID) -> dict[str, Any]:
    row = _first_row(
        """
        WITH latest_payments AS (
            SELECT DISTINCT ON (p.order_id)
                p.order_id,
                COALESCE(NULLIF(TRIM(p.status), ''), 'unpaid') AS payment_status,
                COALESCE(NULLIF(TRIM(p.method), ''), 'unspecified') AS payment_method
            FROM payments p
            ORDER BY p.order_id, COALESCE(p.updated_at, p.created_at) DESC, p.payment_id DESC
        ),
        search_counts AS (
            SELECT COUNT(*)::int AS searches_count
            FROM customer_search_events cs
            WHERE cs.user_id = :user_id
        ),
        like_counts AS (
            SELECT COUNT(*)::int AS likes_count
            FROM product_likes pl
            WHERE pl.user_id = :user_id
        )
        SELECT
            COUNT(*)::int AS total_orders,
            COALESCE(SUM(o.order_total), 0) AS total_spend,
            COALESCE(AVG(o.order_total), 0) AS avg_order_value,
            COALESCE(MAX(o.order_date), NULL) AS last_order_at,
            COUNT(*) FILTER (WHERE LOWER(COALESCE(o.status, '')) = 'completed')::int AS completed_orders,
            COUNT(*) FILTER (
                WHERE LOWER(COALESCE(o.delivery_status, '')) = 'delivered'
                   OR o.delivered_at IS NOT NULL
            )::int AS delivered_orders,
            COUNT(*) FILTER (WHERE LOWER(COALESCE(lp.payment_status, '')) = 'paid')::int AS paid_orders,
            COUNT(*) FILTER (WHERE LOWER(COALESCE(lp.payment_status, '')) = 'refunded')::int AS refunded_orders,
            COALESCE(SUM(CASE WHEN LOWER(COALESCE(lp.payment_status, '')) = 'paid' THEN o.order_total ELSE 0 END), 0) AS paid_spend,
            COALESCE((SELECT searches_count FROM search_counts), 0) AS searches_count,
            COALESCE((SELECT likes_count FROM like_counts), 0) AS likes_count
        FROM orders o
        LEFT JOIN latest_payments lp ON lp.order_id = o.order_id
        WHERE o.buyer_id = :user_id
        """,
        {"user_id": str(user_id)},
    )

    return {
        "total_orders": _as_int(row.get("total_orders"), 0),
        "total_spend": _as_float(row.get("total_spend"), 0.0),
        "avg_order_value": _as_float(row.get("avg_order_value"), 0.0),
        "last_order_at": _iso(row.get("last_order_at")),
        "completed_orders": _as_int(row.get("completed_orders"), 0),
        "delivered_orders": _as_int(row.get("delivered_orders"), 0),
        "paid_orders": _as_int(row.get("paid_orders"), 0),
        "refunded_orders": _as_int(row.get("refunded_orders"), 0),
        "paid_spend": _as_float(row.get("paid_spend"), 0.0),
        "searches_count": _as_int(row.get("searches_count"), 0),
        "likes_count": _as_int(row.get("likes_count"), 0),
        # Current schema does not yet provide a dedicated discount ledger.
        "discount_received": 0.0,
        "discount_tracking_ready": False,
    }


def _build_monthly_spend(user_id: uuid.UUID, months: int = 6) -> list[dict[str, Any]]:
    safe_months = max(3, min(_as_int(months, 6), 18))
    rows = _run_query(
        f"""
        SELECT
            TO_CHAR(DATE_TRUNC('month', o.order_date), 'Mon YYYY') AS month_label,
            DATE_TRUNC('month', o.order_date) AS month_key,
            COALESCE(SUM(o.order_total), 0) AS amount,
            COUNT(*)::int AS orders_count
        FROM orders o
        WHERE o.buyer_id = :user_id
          AND o.order_date >= DATE_TRUNC('month', NOW()) - ((:months - 1) * INTERVAL '1 month')
        GROUP BY DATE_TRUNC('month', o.order_date)
        ORDER BY month_key ASC
        """,
        {"user_id": str(user_id), "months": safe_months},
    )

    return [
        {
            "month": _as_str(r.get("month_label"), "—"),
            "amount": _as_float(r.get("amount"), 0.0),
            "orders_count": _as_int(r.get("orders_count"), 0),
        }
        for r in rows
    ]


def _build_category_spend(user_id: uuid.UUID, limit: int = 6) -> list[dict[str, Any]]:
    safe_limit = max(3, min(_as_int(limit, 6), 12))
    rows = _run_query(
        """
        SELECT
            COALESCE(NULLIF(TRIM(p.category), ''), 'Other') AS category,
            COALESCE(SUM(oi.line_total), 0) AS amount,
            COUNT(DISTINCT o.order_id)::int AS orders_count
        FROM orders o
        JOIN order_items oi ON oi.order_id = o.order_id
        JOIN products p ON p.product_id = oi.product_id
        WHERE o.buyer_id = :user_id
        GROUP BY COALESCE(NULLIF(TRIM(p.category), ''), 'Other')
        ORDER BY amount DESC, category ASC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": safe_limit},
    )

    return [
        {
            "category": _as_str(r.get("category"), "Other"),
            "amount": _as_float(r.get("amount"), 0.0),
            "orders_count": _as_int(r.get("orders_count"), 0),
        }
        for r in rows
    ]


def _build_top_farmers(user_id: uuid.UUID, limit: int = 5) -> list[dict[str, Any]]:
    safe_limit = max(3, min(_as_int(limit, 5), 10))
    rows = _run_query(
        """
        SELECT
            u.id AS farmer_id,
            u.full_name AS farmer_name,
            COALESCE(NULLIF(TRIM(u.location), ''), '') AS location,
            COALESCE(SUM(oi.line_total), 0) AS amount,
            COUNT(DISTINCT o.order_id)::int AS orders_count,
            COUNT(DISTINCT oi.product_id)::int AS products_count,
            MAX(o.order_date) AS last_order_at
        FROM orders o
        JOIN order_items oi ON oi.order_id = o.order_id
        JOIN products p ON p.product_id = oi.product_id
        JOIN users u ON u.id = p.user_id
        WHERE o.buyer_id = :user_id
        GROUP BY u.id, u.full_name, u.location
        ORDER BY amount DESC, orders_count DESC, farmer_name ASC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": safe_limit},
    )

    return [
        {
            "farmer_id": _as_str(r.get("farmer_id"), ""),
            "farmer_name": _as_str(r.get("farmer_name"), "Farmer"),
            "location": _as_str(r.get("location"), ""),
            "amount": _as_float(r.get("amount"), 0.0),
            "orders_count": _as_int(r.get("orders_count"), 0),
            "products_count": _as_int(r.get("products_count"), 0),
            "last_order_at": _iso(r.get("last_order_at")),
        }
        for r in rows
    ]


def _build_repeat_purchases(user_id: uuid.UUID, limit: int = 6) -> list[dict[str, Any]]:
    safe_limit = max(3, min(_as_int(limit, 6), 12))
    rows = _run_query(
        """
        SELECT
            p.product_id,
            p.product_name,
            COALESCE(NULLIF(TRIM(p.category), ''), 'Other') AS category,
            COUNT(DISTINCT o.order_id)::int AS purchase_count,
            MAX(o.order_date) AS last_order_at,
            COALESCE(SUM(oi.line_total), 0) AS amount
        FROM orders o
        JOIN order_items oi ON oi.order_id = o.order_id
        JOIN products p ON p.product_id = oi.product_id
        WHERE o.buyer_id = :user_id
        GROUP BY p.product_id, p.product_name, p.category
        HAVING COUNT(DISTINCT o.order_id) > 1
        ORDER BY purchase_count DESC, amount DESC, p.product_name ASC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": safe_limit},
    )

    return [
        {
            "product_id": _as_str(r.get("product_id"), ""),
            "product_name": _as_str(r.get("product_name"), "Product"),
            "category": _as_str(r.get("category"), "Other"),
            "purchase_count": _as_int(r.get("purchase_count"), 0),
            "last_order_at": _iso(r.get("last_order_at")),
            "amount": _as_float(r.get("amount"), 0.0),
        }
        for r in rows
    ]


def _build_recent_searches(user_id: uuid.UUID, limit: int = 10) -> list[dict[str, Any]]:
    safe_limit = max(5, min(_as_int(limit, 10), 20))
    rows = _run_query(
        """
        SELECT query, created_at
        FROM customer_search_events
        WHERE user_id = :user_id
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": safe_limit},
    )

    return [
        {
            "query": _as_str(r.get("query"), ""),
            "created_at": _iso(r.get("created_at")),
        }
        for r in rows
        if _as_str(r.get("query"), "")
    ]


def _build_liked_products(user_id: uuid.UUID, limit: int = 8) -> list[dict[str, Any]]:
    safe_limit = max(4, min(_as_int(limit, 8), 16))
    rows = _run_query(
        """
        SELECT
            p.product_id,
            p.product_name,
            p.category,
            p.price,
            p.image_url,
            COALESCE(NULLIF(TRIM(u.full_name), ''), 'Farmer') AS farmer_name,
            COALESCE(pl.updated_at, pl.created_at) AS liked_at
        FROM product_likes pl
        JOIN products p ON p.product_id = pl.product_id
        LEFT JOIN users u ON u.id = p.user_id
        WHERE pl.user_id = :user_id
        ORDER BY COALESCE(pl.updated_at, pl.created_at) DESC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": safe_limit},
    )

    return [
        {
            "product_id": _as_str(r.get("product_id"), ""),
            "product_name": _as_str(r.get("product_name"), "Product"),
            "category": _as_str(r.get("category"), "Other"),
            "price": _as_float(r.get("price"), 0.0),
            "image_url": _as_str(r.get("image_url"), ""),
            "farmer_name": _as_str(r.get("farmer_name"), "Farmer"),
            "liked_at": _iso(r.get("liked_at")),
        }
        for r in rows
    ]


def _build_payment_mix(user_id: uuid.UUID, limit: int = 5) -> list[dict[str, Any]]:
    safe_limit = max(3, min(_as_int(limit, 5), 10))
    rows = _run_query(
        """
        WITH latest_payments AS (
            SELECT DISTINCT ON (p.order_id)
                p.order_id,
                COALESCE(NULLIF(TRIM(p.method), ''), 'unspecified') AS payment_method,
                COALESCE(p.amount, 0) AS amount,
                COALESCE(NULLIF(TRIM(p.status), ''), 'unpaid') AS payment_status
            FROM payments p
            ORDER BY p.order_id, COALESCE(p.updated_at, p.created_at) DESC, p.payment_id DESC
        )
        SELECT
            payment_method,
            COUNT(*)::int AS orders_count,
            COALESCE(SUM(amount), 0) AS amount
        FROM latest_payments lp
        JOIN orders o ON o.order_id = lp.order_id
        WHERE o.buyer_id = :user_id
        GROUP BY payment_method
        ORDER BY amount DESC, orders_count DESC, payment_method ASC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": safe_limit},
    )

    return [
        {
            "payment_method": _as_str(r.get("payment_method"), "unspecified"),
            "orders_count": _as_int(r.get("orders_count"), 0),
            "amount": _as_float(r.get("amount"), 0.0),
        }
        for r in rows
    ]


def _build_customer_segmentation(
    *,
    summary: dict[str, Any],
    category_spend: Iterable[dict[str, Any]],
    top_farmers: Iterable[dict[str, Any]],
    user_location: str,
) -> dict[str, Any]:
    categories = list(category_spend)
    farmers = list(top_farmers)

    total_orders = _as_int(summary.get("total_orders"), 0)
    total_spend = _as_float(summary.get("total_spend"), 0.0)
    avg_order_value = _as_float(summary.get("avg_order_value"), 0.0)
    searches_count = _as_int(summary.get("searches_count"), 0)
    likes_count = _as_int(summary.get("likes_count"), 0)

    user_loc = _as_str(user_location, "").lower()
    top_category_amount = _as_float(categories[0].get("amount"), 0.0) if categories else 0.0
    top_category_name = _as_str(categories[0].get("category"), "") if categories else ""
    top_category_share_pct = _pct(top_category_amount, total_spend)

    top_farmer = farmers[0] if farmers else {}
    top_farmer_name = _as_str(top_farmer.get("farmer_name"), "")
    top_farmer_orders = _as_int(top_farmer.get("orders_count"), 0)
    top_farmer_share_pct = _pct(top_farmer_orders, total_orders)
    top_farmer_location = _as_str(top_farmer.get("location"), "").lower()
    loyal_local_match = bool(user_loc and top_farmer_location and user_loc == top_farmer_location)

    segments: list[dict[str, Any]] = []

    if total_orders <= 1:
        segments.append(
            {
                "label": "Occasional buyer",
                "confidence": "high",
                "reason": "The customer has one or fewer recorded orders so far.",
            }
        )
    else:
        segments.append(
            {
                "label": "Repeat buyer",
                "confidence": "high",
                "reason": f"The customer has already placed {total_orders} orders.",
            }
        )

    if total_spend >= 1500 or avg_order_value >= 300:
        segments.append(
            {
                "label": "High-value customer",
                "confidence": "medium",
                "reason": f"Recorded spend is N$ {total_spend:.2f} with an average basket of N$ {avg_order_value:.2f}.",
            }
        )

    if total_orders >= 2 and top_category_share_pct >= 60 and top_category_name:
        segments.append(
            {
                "label": "Category specialist",
                "confidence": "medium",
                "reason": f"{top_category_name} contributes {top_category_share_pct:.0f}% of recorded spend.",
            }
        )

    if total_orders >= 3 and top_farmer_share_pct >= 60 and top_farmer_name:
        segments.append(
            {
                "label": "Loyal local buyer" if loyal_local_match else "Loyal buyer",
                "confidence": "medium",
                "reason": f"{top_farmer_name} accounts for {top_farmer_share_pct:.0f}% of recorded order relationships.",
            }
        )

    if total_orders >= 1 and avg_order_value <= 150 and searches_count >= max(5, total_orders * 3):
        segments.append(
            {
                "label": "Price-sensitive buyer",
                "confidence": "low",
                "reason": "Search activity is high relative to completed orders while average basket size remains modest.",
            }
        )

    priority = {
        "Loyal local buyer": 1,
        "Loyal buyer": 2,
        "High-value customer": 3,
        "Category specialist": 4,
        "Price-sensitive buyer": 5,
        "Repeat buyer": 6,
        "Occasional buyer": 7,
    }

    unique_segments: list[dict[str, Any]] = []
    seen_labels: set[str] = set()
    for seg in segments:
        label = _as_str(seg.get("label"), "")
        if not label or label in seen_labels:
            continue
        unique_segments.append(seg)
        seen_labels.add(label)

    unique_segments.sort(key=lambda item: priority.get(_as_str(item.get("label"), ""), 99))
    primary_segment = unique_segments[0] if unique_segments else {
        "label": "Occasional buyer",
        "confidence": "low",
        "reason": "Not enough activity is available yet to classify the customer more deeply.",
    }

    return {
        "primary_segment": primary_segment,
        "segments": unique_segments,
        "metrics": {
            "top_farmer_share_pct": top_farmer_share_pct,
            "top_category_share_pct": top_category_share_pct,
            "searches_count": searches_count,
            "likes_count": likes_count,
            "total_orders": total_orders,
            "total_spend": total_spend,
            "avg_order_value": avg_order_value,
        },
    }


def _build_reorder_intelligence(user_id: uuid.UUID, limit: int = 5) -> list[dict[str, Any]]:
    safe_limit = max(3, min(_as_int(limit, 5), 10))
    rows = _run_query(
        """
        WITH ordered_items AS (
            SELECT
                p.product_id,
                p.product_name,
                COALESCE(NULLIF(TRIM(p.category), ''), 'Other') AS category,
                p.price AS current_price,
                p.quantity AS available_qty,
                o.order_date,
                oi.unit_price,
                EXTRACT(EPOCH FROM (
                    o.order_date - LAG(o.order_date) OVER (
                        PARTITION BY p.product_id
                        ORDER BY o.order_date
                    )
                )) / 86400.0 AS gap_days
            FROM orders o
            JOIN order_items oi ON oi.order_id = o.order_id
            JOIN products p ON p.product_id = oi.product_id
            WHERE o.buyer_id = :user_id
        )
        SELECT
            product_id,
            product_name,
            category,
            COUNT(*)::int AS purchase_count,
            MAX(order_date) AS last_order_at,
            COALESCE(AVG(unit_price), 0) AS avg_paid_unit_price,
            COALESCE(MAX(current_price), 0) AS current_price,
            COALESCE(MAX(available_qty), 0) AS available_qty,
            COALESCE(AVG(gap_days) FILTER (WHERE gap_days IS NOT NULL), 0) AS avg_gap_days
        FROM ordered_items
        GROUP BY product_id, product_name, category
        HAVING COUNT(*) > 1
        ORDER BY purchase_count DESC, MAX(order_date) DESC, product_name ASC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": safe_limit},
    )

    now_dt = datetime.utcnow()
    suggestions: list[dict[str, Any]] = []

    for row in rows:
        last_order_dt = _dt(row.get("last_order_at"))
        days_since_last_order = 0
        if last_order_dt is not None:
            days_since_last_order = max(0, (now_dt - last_order_dt).days)

        avg_gap_days = round(_as_float(row.get("avg_gap_days"), 0.0), 1)
        current_price = _as_float(row.get("current_price"), 0.0)
        avg_paid_unit_price = _as_float(row.get("avg_paid_unit_price"), 0.0)
        available_qty = _as_float(row.get("available_qty"), 0.0)
        price_delta_pct = _pct(current_price - avg_paid_unit_price, avg_paid_unit_price) if avg_paid_unit_price > 0 else 0.0

        reorder_stage = "watch"
        if avg_gap_days > 0:
            if days_since_last_order >= avg_gap_days * 0.9:
                reorder_stage = "due_now"
            elif days_since_last_order >= avg_gap_days * 0.6:
                reorder_stage = "approaching"

        low_stock_risk = available_qty > 0 and available_qty <= 5

        recommendation_parts: list[str] = []
        if reorder_stage == "due_now":
            recommendation_parts.append("Reorder timing is due now based on past buying cadence.")
        elif reorder_stage == "approaching":
            recommendation_parts.append("Reorder timing is approaching based on past buying cadence.")
        else:
            recommendation_parts.append("Continue monitoring reorder timing.")

        if price_delta_pct >= 10:
            recommendation_parts.append("Current price is materially above the customer’s historical average paid price.")
        elif price_delta_pct <= -10:
            recommendation_parts.append("Current price is below the customer’s historical average paid price.")

        if low_stock_risk:
            recommendation_parts.append("Available stock is currently low, so substitution or early reorder should be considered.")

        suggestions.append(
            {
                "product_id": _as_str(row.get("product_id"), ""),
                "product_name": _as_str(row.get("product_name"), "Product"),
                "category": _as_str(row.get("category"), "Other"),
                "purchase_count": _as_int(row.get("purchase_count"), 0),
                "last_order_at": _iso(row.get("last_order_at")),
                "days_since_last_order": days_since_last_order,
                "avg_gap_days": avg_gap_days,
                "current_price": current_price,
                "avg_paid_unit_price": avg_paid_unit_price,
                "price_delta_pct": round(price_delta_pct, 2),
                "available_qty": available_qty,
                "low_stock_risk": low_stock_risk,
                "reorder_stage": reorder_stage,
                "substitute_hint": f"Compare current {_as_str(row.get('category'), 'similar').lower()} options if availability or price has changed.",
                "recommendation": " ".join(recommendation_parts),
            }
        )

    stage_priority = {"due_now": 1, "approaching": 2, "watch": 3}
    suggestions.sort(
        key=lambda item: (
            stage_priority.get(_as_str(item.get("reorder_stage"), "watch"), 9),
            0 if item.get("low_stock_risk") else 1,
            -_as_int(item.get("purchase_count"), 0),
        )
    )

    return suggestions


def _build_delivery_fee_share(user_id: uuid.UUID) -> dict[str, Any]:
    row = _first_row(
        """
        SELECT
            COUNT(*)::int AS total_orders,
            COUNT(*) FILTER (WHERE COALESCE(o.delivery_fee, 0) > 0)::int AS orders_with_delivery_fee,
            COUNT(*) FILTER (WHERE COALESCE(o.delivery_fee, 0) = 0)::int AS fee_free_orders,
            COALESCE(SUM(o.delivery_fee), 0) AS total_delivery_fees,
            COALESCE(AVG(NULLIF(o.delivery_fee, 0)), 0) AS avg_delivery_fee_nonzero,
            COALESCE(SUM(o.order_total), 0) AS total_order_value
        FROM orders o
        WHERE o.buyer_id = :user_id
        """,
        {"user_id": str(user_id)},
    )

    total_delivery_fees = _as_float(row.get("total_delivery_fees"), 0.0)
    total_order_value = _as_float(row.get("total_order_value"), 0.0)

    return {
        "total_orders": _as_int(row.get("total_orders"), 0),
        "orders_with_delivery_fee": _as_int(row.get("orders_with_delivery_fee"), 0),
        "fee_free_orders": _as_int(row.get("fee_free_orders"), 0),
        "total_delivery_fees": total_delivery_fees,
        "avg_delivery_fee_nonzero": _as_float(row.get("avg_delivery_fee_nonzero"), 0.0),
        "delivery_fee_share_pct": _pct(total_delivery_fees, total_order_value),
    }


def _build_trust_metrics(user_id: uuid.UUID) -> dict[str, Any]:
    row = _first_row(
        """
        WITH latest_payments AS (
            SELECT DISTINCT ON (p.order_id)
                p.order_id,
                COALESCE(NULLIF(TRIM(p.status), ''), 'unpaid') AS payment_status,
                p.proof_url
            FROM payments p
            ORDER BY p.order_id, COALESCE(p.updated_at, p.created_at) DESC, p.payment_id DESC
        )
        SELECT
            COUNT(*)::int AS total_orders,
            COUNT(*) FILTER (
                WHERE LOWER(COALESCE(lp.payment_status, '')) IN ('paid', 'refunded')
            )::int AS payment_confirmed_orders,
            COUNT(*) FILTER (
                WHERE COALESCE(NULLIF(TRIM(lp.proof_url), ''), '') <> ''
            )::int AS proof_received_orders,
            COUNT(*) FILTER (
                WHERE LOWER(COALESCE(o.delivery_status, '')) = 'delivered'
                   OR o.delivered_at IS NOT NULL
            )::int AS delivered_orders,
            COUNT(*) FILTER (
                WHERE o.expected_delivery_date IS NOT NULL
                  AND o.delivered_at IS NOT NULL
            )::int AS comparable_deliveries,
            COUNT(*) FILTER (
                WHERE o.expected_delivery_date IS NOT NULL
                  AND o.delivered_at IS NOT NULL
                  AND o.delivered_at <= o.expected_delivery_date
            )::int AS on_time_deliveries,
            COUNT(*) FILTER (
                WHERE LOWER(COALESCE(lp.payment_status, '')) = 'refunded'
            )::int AS refunded_orders
        FROM orders o
        LEFT JOIN latest_payments lp ON lp.order_id = o.order_id
        WHERE o.buyer_id = :user_id
        """,
        {"user_id": str(user_id)},
    )

    total_orders = _as_int(row.get("total_orders"), 0)
    payment_confirmed_orders = _as_int(row.get("payment_confirmed_orders"), 0)
    proof_received_orders = _as_int(row.get("proof_received_orders"), 0)
    delivered_orders = _as_int(row.get("delivered_orders"), 0)
    comparable_deliveries = _as_int(row.get("comparable_deliveries"), 0)
    on_time_deliveries = _as_int(row.get("on_time_deliveries"), 0)
    refunded_orders = _as_int(row.get("refunded_orders"), 0)

    available_scores = [
        _pct(payment_confirmed_orders, total_orders),
        _pct(proof_received_orders, total_orders),
        _pct(delivered_orders, total_orders),
    ]
    if comparable_deliveries > 0:
        available_scores.append(_pct(on_time_deliveries, comparable_deliveries))

    transparency_score = round(sum(available_scores) / len(available_scores), 2) if available_scores else 0.0

    return {
        "proof_received_orders": proof_received_orders,
        "proof_received_rate_pct": _pct(proof_received_orders, total_orders),
        "payment_confirmed_orders": payment_confirmed_orders,
        "payment_confirmed_rate_pct": _pct(payment_confirmed_orders, total_orders),
        "delivered_orders": delivered_orders,
        "delivery_completed_rate_pct": _pct(delivered_orders, total_orders),
        "refunded_orders": refunded_orders,
        "refund_visibility_rate_pct": _pct(refunded_orders, total_orders),
        "comparable_deliveries": comparable_deliveries,
        "on_time_deliveries": on_time_deliveries,
        "on_time_delivery_rate_pct": _pct(on_time_deliveries, comparable_deliveries),
        "farmer_response_time_ready": False,
        "farmer_response_time_note": "A dedicated farmer response-time event model is not yet available in the current schema.",
        "transparency_score": transparency_score,
    }


def _build_notes(
    *,
    summary: dict[str, Any],
    category_spend: Iterable[dict[str, Any]],
    top_farmers: Iterable[dict[str, Any]],
    segmentation: dict[str, Any],
    delivery_fee_share: dict[str, Any],
    trust_metrics: dict[str, Any],
    reorder_intelligence: Iterable[dict[str, Any]],
) -> list[str]:
    notes: list[str] = []

    categories = list(category_spend)
    farmers = list(top_farmers)
    reorder_rows = list(reorder_intelligence)

    total_orders = _as_int(summary.get("total_orders"), 0)
    avg_order_value = _as_float(summary.get("avg_order_value"), 0.0)
    likes_count = _as_int(summary.get("likes_count"), 0)
    searches_count = _as_int(summary.get("searches_count"), 0)

    primary_segment = segmentation.get("primary_segment") or {}
    primary_segment_label = _as_str(primary_segment.get("label"), "")
    primary_segment_reason = _as_str(primary_segment.get("reason"), "")

    if total_orders > 0:
        notes.append(
            f"You have placed {total_orders} order(s) with an average basket value of N$ {avg_order_value:.2f}."
        )

    if primary_segment_label:
        notes.append(f"Current segment: {primary_segment_label}. {primary_segment_reason}")

    if categories:
        top_category = categories[0]
        notes.append(
            f"Your strongest spending category is {top_category['category']} at N$ {top_category['amount']:.2f}."
        )

    if farmers:
        top_farmer = farmers[0]
        notes.append(
            f"Your top farmer relationship is {top_farmer['farmer_name']} with N$ {top_farmer['amount']:.2f} across {top_farmer['orders_count']} order(s)."
        )

    delivery_fee_share_pct = _as_float(delivery_fee_share.get("delivery_fee_share_pct"), 0.0)
    if delivery_fee_share_pct > 0:
        notes.append(
            f"Delivery fees account for {delivery_fee_share_pct:.0f}% of recorded order value."
        )

    transparency_score = _as_float(trust_metrics.get("transparency_score"), 0.0)
    if transparency_score > 0:
        notes.append(
            f"Trust and transparency signals currently average {transparency_score:.0f}% across proof, payment confirmation, and delivery visibility."
        )

    if reorder_rows:
        lead_reorder = reorder_rows[0]
        notes.append(
            f"{lead_reorder['product_name']} is the strongest reorder candidate right now, with stage {lead_reorder['reorder_stage'].replace('_', ' ')}."
        )

    if searches_count > 0 or likes_count > 0:
        notes.append(
            f"Discovery signals recorded so far: {searches_count} search(es) and {likes_count} liked product(s)."
        )

    if not notes:
        notes.append(
            "Insights will appear here as the customer places orders, searches products, and saves favorites."
        )

    return notes[:6]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@customer_insights_bp.get("/insights")
@customer_insights_bp.get("/insights/summary")
@require_auth("customer")
def get_customer_insights() -> Any:
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"success": False, "message": "Invalid user."}), 401

    months = max(3, min(_as_int(request.args.get("months"), 6), 18))

    summary = _build_summary(user_id)
    monthly_spend = _build_monthly_spend(user_id, months=months)
    category_spend = _build_category_spend(user_id)
    top_farmers = _build_top_farmers(user_id)
    repeat_purchases = _build_repeat_purchases(user_id)
    recent_searches = _build_recent_searches(user_id)
    liked_products = _build_liked_products(user_id)
    payment_mix = _build_payment_mix(user_id)
    segmentation = _build_customer_segmentation(
        summary=summary,
        category_spend=category_spend,
        top_farmers=top_farmers,
        user_location=_current_user_location(),
    )
    reorder_intelligence = _build_reorder_intelligence(user_id)
    delivery_fee_share = _build_delivery_fee_share(user_id)
    trust_metrics = _build_trust_metrics(user_id)
    notes = _build_notes(
        summary=summary,
        category_spend=category_spend,
        top_farmers=top_farmers,
        segmentation=segmentation,
        delivery_fee_share=delivery_fee_share,
        trust_metrics=trust_metrics,
        reorder_intelligence=reorder_intelligence,
    )

    return jsonify(
        {
            "success": True,
            "summary": summary,
            "spending_by_month": monthly_spend,
            "spend_by_category": category_spend,
            "top_farmers": top_farmers,
            "repeat_purchases": repeat_purchases,
            "recent_searches": recent_searches,
            "liked_products": liked_products,
            "payment_mix": payment_mix,
            "segmentation": segmentation,
            "reorder_intelligence": reorder_intelligence,
            "delivery_fee_share": delivery_fee_share,
            "trust_metrics": trust_metrics,
            "notes": notes,
            "months": months,
        }
    ), 200