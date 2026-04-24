from __future__ import annotations

# ============================================================================
# backend/routes/customer_workspace.py — Customer Saved/Search + Payments + Account
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Phase-1 customer workspace endpoints used by:
#     • Saved & Search
#     • Payments
#     • Account
#
# DESIGN GOALS:
#   ✅ Works with the current AgroConnect schema without requiring Phase-2 tables
#   ✅ Uses only the authenticated customer context
#   ✅ Keeps responses UI-ready for a modern ecommerce dashboard
#   ✅ Limits this workspace to active customer discovery, payments, and account
#      concerns only
# ============================================================================

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from flask.blueprints import Blueprint
from flask.globals import current_app, request
from flask.json import jsonify
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from backend.database.db import db
from backend.utils.require_auth import require_auth

customer_workspace_bp = Blueprint("customer_workspace", __name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe_uuid(value: Any) -> Optional[uuid.UUID]:
    """Safely coerce a value into UUID form."""
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value).strip())
    except Exception:
        return None


def _as_int(value: Any, default: int = 0) -> int:
    """Best-effort integer cast."""
    try:
        return int(value)
    except Exception:
        return default


def _as_float(value: Any, default: float = 0.0) -> float:
    """Best-effort float cast with Decimal support."""
    if value is None:
        return default
    if isinstance(value, Decimal):
        return float(value)
    try:
        return float(value)
    except Exception:
        return default


def _as_str(value: Any, default: str = "") -> str:
    """Best-effort clean string cast."""
    if value is None:
        return default
    try:
        s = str(value).strip()
    except Exception:
        return default
    return s or default


def _as_bool(value: Any, default: bool = False) -> bool:
    """Best-effort boolean coercion."""
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return value != 0
    s = _as_str(value, "").lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _iso(value: Any) -> Optional[str]:
    """Return an ISO 8601 string when possible."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    try:
        parsed = datetime.fromisoformat(str(value))
        return parsed.isoformat()
    except Exception:
        return _as_str(value, default="") or None


def _current_user_id() -> Optional[uuid.UUID]:
    """Resolve the authenticated current user's UUID."""
    user = getattr(request, "current_user", None)
    return _safe_uuid(getattr(user, "id", None) or getattr(user, "user_id", None))


def _current_user_dict() -> dict[str, Any]:
    """
    Build a defensive current-user dictionary.

    This version keeps additional timeline/account metadata available when the
    auth user object exposes them.
    """
    user = getattr(request, "current_user", None)
    if user is None:
        return {}
    if hasattr(user, "to_dict"):
        try:
            payload = user.to_dict()
            if isinstance(payload, dict):
                payload.setdefault("id", getattr(user, "id", None))
                payload.setdefault("full_name", getattr(user, "full_name", None))
                payload.setdefault("phone", getattr(user, "phone", None))
                payload.setdefault("email", getattr(user, "email", None))
                payload.setdefault("location", getattr(user, "location", None))
                payload.setdefault("role", getattr(user, "role", None))
                payload.setdefault("created_at", getattr(user, "created_at", None))
                payload.setdefault("updated_at", getattr(user, "updated_at", None))
                payload.setdefault("last_login_at", getattr(user, "last_login_at", None))
                payload.setdefault("last_seen_at", getattr(user, "last_seen_at", None))
                return payload
        except Exception:
            pass
    return {
        "id": getattr(user, "id", None),
        "full_name": getattr(user, "full_name", None),
        "phone": getattr(user, "phone", None),
        "email": getattr(user, "email", None),
        "location": getattr(user, "location", None),
        "role": getattr(user, "role", None),
        "created_at": getattr(user, "created_at", None),
        "updated_at": getattr(user, "updated_at", None),
        "last_login_at": getattr(user, "last_login_at", None),
        "last_seen_at": getattr(user, "last_seen_at", None),
    }


def _run_query(sql: str, params: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
    """
    Execute raw SQL and return mapping rows as plain dictionaries.

    The workspace is intentionally tolerant of schema drift. Query failures are
    logged and surfaced as empty datasets instead of crashing the API.
    """
    try:
        rows = db.session.execute(text(sql), params or {}).mappings().all()
        return [dict(row) for row in rows]
    except SQLAlchemyError:
        current_app.logger.exception("Customer workspace query failed")
        return []


def _first_row(sql: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Return the first row from a raw SQL query, or an empty dict."""
    rows = _run_query(sql, params)
    return rows[0] if rows else {}


# ---------------------------------------------------------------------------
# Saved & search builders
# ---------------------------------------------------------------------------
def _build_recent_searches(user_id: uuid.UUID, limit: int = 12) -> list[dict[str, Any]]:
    """Return recent search phrases performed by the customer."""
    rows = _run_query(
        """
        SELECT query, created_at
        FROM customer_search_events
        WHERE user_id = :user_id
        ORDER BY created_at DESC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": max(5, min(_as_int(limit, 12), 20))},
    )
    return [
        {"query": _as_str(r.get("query"), ""), "created_at": _iso(r.get("created_at"))}
        for r in rows
        if _as_str(r.get("query"), "")
    ]


def _build_liked_products(user_id: uuid.UUID, limit: int = 12) -> list[dict[str, Any]]:
    """Return products liked by the customer for discovery memory."""
    rows = _run_query(
        """
        SELECT
            p.product_id,
            p.product_name,
            COALESCE(NULLIF(TRIM(p.category), ''), 'Other') AS category,
            COALESCE(p.price, 0) AS price,
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
        {"user_id": str(user_id), "limit": max(6, min(_as_int(limit, 12), 24))},
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


def _build_recently_viewed(user_id: uuid.UUID, limit: int = 10) -> list[dict[str, Any]]:
    """Return recently viewed products with engagement counts."""
    rows = _run_query(
        """
        WITH ranked_views AS (
            SELECT
                pe.product_id,
                MAX(pe.created_at) AS last_viewed_at,
                COUNT(*)::int AS views_count
            FROM product_engagement_events pe
            WHERE pe.user_id = :user_id
              AND LOWER(COALESCE(pe.event_type, '')) = 'view'
            GROUP BY pe.product_id
        )
        SELECT
            rv.product_id,
            p.product_name,
            COALESCE(NULLIF(TRIM(p.category), ''), 'Other') AS category,
            COALESCE(p.price, 0) AS price,
            p.image_url,
            rv.views_count,
            rv.last_viewed_at,
            COALESCE(NULLIF(TRIM(u.full_name), ''), 'Farmer') AS farmer_name
        FROM ranked_views rv
        JOIN products p ON p.product_id = rv.product_id
        LEFT JOIN users u ON u.id = p.user_id
        ORDER BY rv.last_viewed_at DESC, rv.views_count DESC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": max(6, min(_as_int(limit, 10), 20))},
    )
    return [
        {
            "product_id": _as_str(r.get("product_id"), ""),
            "product_name": _as_str(r.get("product_name"), "Product"),
            "category": _as_str(r.get("category"), "Other"),
            "price": _as_float(r.get("price"), 0.0),
            "image_url": _as_str(r.get("image_url"), ""),
            "views_count": _as_int(r.get("views_count"), 0),
            "last_viewed_at": _iso(r.get("last_viewed_at")),
            "farmer_name": _as_str(r.get("farmer_name"), "Farmer"),
        }
        for r in rows
    ]


def _build_repeat_purchases(user_id: uuid.UUID, limit: int = 8) -> list[dict[str, Any]]:
    """Return repeat-purchase candidates derived from historical orders."""
    rows = _run_query(
        """
        SELECT
            p.product_id,
            p.product_name,
            COALESCE(NULLIF(TRIM(p.category), ''), 'Other') AS category,
            COUNT(DISTINCT o.order_id)::int AS purchase_count,
            MAX(o.order_date) AS last_order_at,
            COALESCE(SUM(oi.line_total), 0) AS amount,
            COALESCE(NULLIF(TRIM(u.full_name), ''), 'Farmer') AS farmer_name
        FROM orders o
        JOIN order_items oi ON oi.order_id = o.order_id
        JOIN products p ON p.product_id = oi.product_id
        LEFT JOIN users u ON u.id = p.user_id
        WHERE o.buyer_id = :user_id
        GROUP BY p.product_id, p.product_name, p.category, u.full_name
        HAVING COUNT(DISTINCT o.order_id) > 1
        ORDER BY purchase_count DESC, amount DESC, p.product_name ASC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": max(4, min(_as_int(limit, 8), 16))},
    )
    return [
        {
            "product_id": _as_str(r.get("product_id"), ""),
            "product_name": _as_str(r.get("product_name"), "Product"),
            "category": _as_str(r.get("category"), "Other"),
            "purchase_count": _as_int(r.get("purchase_count"), 0),
            "last_order_at": _iso(r.get("last_order_at")),
            "amount": _as_float(r.get("amount"), 0.0),
            "farmer_name": _as_str(r.get("farmer_name"), "Farmer"),
        }
        for r in rows
    ]


def _build_behavior_funnel(user_id: uuid.UUID) -> dict[str, Any]:
    """
    Build a compact customer behavior funnel.

    This remains useful for recommendation and commerce insight without
    introducing refund/dispute workflow concepts.
    """
    row = _first_row(
        """
        WITH latest_payments AS (
            SELECT DISTINCT ON (p.order_id)
                p.order_id,
                COALESCE(NULLIF(TRIM(p.status), ''), 'unpaid') AS payment_status
            FROM payments p
            ORDER BY p.order_id, COALESCE(p.updated_at, p.created_at) DESC, p.payment_id DESC
        )
        SELECT
            (SELECT COUNT(*)::int FROM customer_search_events cs WHERE cs.user_id = :user_id) AS searched,
            (
                SELECT COUNT(*)::int
                FROM product_engagement_events pe
                WHERE pe.user_id = :user_id
                  AND LOWER(COALESCE(pe.event_type, '')) = 'view'
            ) AS viewed,
            (SELECT COUNT(*)::int FROM product_likes pl WHERE pl.user_id = :user_id) AS liked,
            (SELECT COUNT(*)::int FROM cart_items ci WHERE ci.user_id = :user_id) AS added_to_cart,
            (SELECT COUNT(*)::int FROM orders o WHERE o.buyer_id = :user_id) AS checked_out,
            (
                SELECT COUNT(*)::int
                FROM orders o
                LEFT JOIN latest_payments lp ON lp.order_id = o.order_id
                WHERE o.buyer_id = :user_id
                  AND LOWER(COALESCE(lp.payment_status, '')) IN ('paid', 'refunded')
            ) AS paid,
            (
                SELECT COUNT(*)::int
                FROM orders o
                WHERE o.buyer_id = :user_id
                  AND LOWER(COALESCE(o.status, '')) = 'completed'
            ) AS completed
        """,
        {"user_id": str(user_id)},
    )
    return {
        "searched": _as_int(row.get("searched"), 0),
        "viewed": _as_int(row.get("viewed"), 0),
        "liked": _as_int(row.get("liked"), 0),
        "added_to_cart": _as_int(row.get("added_to_cart"), 0),
        "checked_out": _as_int(row.get("checked_out"), 0),
        "paid": _as_int(row.get("paid"), 0),
        "completed": _as_int(row.get("completed"), 0),
        "cart_is_current_state_only": True,
    }


# ---------------------------------------------------------------------------
# Payments builders
# ---------------------------------------------------------------------------
def _build_payment_history(user_id: uuid.UUID, limit: int = 24) -> list[dict[str, Any]]:
    """Return order-linked customer payment records."""
    rows = _run_query(
        """
        WITH latest_payments AS (
            SELECT DISTINCT ON (p.order_id)
                p.payment_id,
                p.order_id,
                COALESCE(p.amount, 0) AS amount,
                COALESCE(NULLIF(TRIM(p.status), ''), 'unpaid') AS payment_status,
                COALESCE(NULLIF(TRIM(p.method), ''), 'unspecified') AS payment_method,
                COALESCE(NULLIF(TRIM(p.reference), ''), '') AS payment_reference,
                p.proof_url,
                p.proof_uploaded_at,
                p.created_at,
                p.updated_at
            FROM payments p
            ORDER BY p.order_id, COALESCE(p.updated_at, p.created_at) DESC, p.payment_id DESC
        )
        SELECT
            o.order_id,
            o.order_date,
            COALESCE(o.order_total, 0) AS order_total,
            COALESCE(NULLIF(TRIM(o.status), ''), 'pending') AS order_status,
            COALESCE(NULLIF(TRIM(o.delivery_status), ''), 'pending') AS delivery_status,
            lp.payment_id,
            lp.amount,
            lp.payment_status,
            lp.payment_method,
            lp.payment_reference,
            lp.proof_url,
            lp.proof_uploaded_at,
            lp.created_at,
            lp.updated_at
        FROM orders o
        LEFT JOIN latest_payments lp ON lp.order_id = o.order_id
        WHERE o.buyer_id = :user_id
        ORDER BY o.order_date DESC, lp.updated_at DESC NULLS LAST
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": max(12, min(_as_int(limit, 24), 50))},
    )
    return [
        {
            "order_id": _as_str(r.get("order_id"), ""),
            "order_date": _iso(r.get("order_date")),
            "order_total": _as_float(r.get("order_total"), 0.0),
            "order_status": _as_str(r.get("order_status"), "pending"),
            "delivery_status": _as_str(r.get("delivery_status"), "pending"),
            "payment_id": _as_int(r.get("payment_id"), 0),
            "amount": _as_float(r.get("amount"), 0.0),
            "payment_status": _as_str(r.get("payment_status"), "unpaid"),
            "payment_method": _as_str(r.get("payment_method"), "unspecified"),
            "payment_reference": _as_str(r.get("payment_reference"), ""),
            "proof_url": _as_str(r.get("proof_url"), ""),
            "proof_uploaded_at": _iso(r.get("proof_uploaded_at")),
            "created_at": _iso(r.get("created_at")),
            "updated_at": _iso(r.get("updated_at")),
        }
        for r in rows
    ]


def _build_payment_methods_used(user_id: uuid.UUID) -> list[dict[str, Any]]:
    """Aggregate payment methods used by the customer."""
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
        """,
        {"user_id": str(user_id)},
    )
    return [
        {
            "payment_method": _as_str(r.get("payment_method"), "unspecified"),
            "orders_count": _as_int(r.get("orders_count"), 0),
            "amount": _as_float(r.get("amount"), 0.0),
        }
        for r in rows
    ]


def _build_proof_archive(user_id: uuid.UUID, limit: int = 12) -> list[dict[str, Any]]:
    """Return available proof-of-payment records for customer visibility."""
    rows = _run_query(
        """
        SELECT
            p.payment_id,
            p.order_id,
            COALESCE(p.amount, 0) AS amount,
            COALESCE(NULLIF(TRIM(p.method), ''), 'unspecified') AS payment_method,
            COALESCE(NULLIF(TRIM(p.reference), ''), '') AS payment_reference,
            p.proof_url,
            p.proof_uploaded_at,
            COALESCE(NULLIF(TRIM(p.status), ''), 'unpaid') AS payment_status,
            o.order_date
        FROM payments p
        JOIN orders o ON o.order_id = p.order_id
        WHERE o.buyer_id = :user_id
          AND p.proof_url IS NOT NULL
          AND TRIM(COALESCE(p.proof_url, '')) <> ''
        ORDER BY COALESCE(p.proof_uploaded_at, p.updated_at, p.created_at) DESC, p.payment_id DESC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": max(6, min(_as_int(limit, 12), 30))},
    )
    return [
        {
            "payment_id": _as_int(r.get("payment_id"), 0),
            "order_id": _as_str(r.get("order_id"), ""),
            "order_date": _iso(r.get("order_date")),
            "amount": _as_float(r.get("amount"), 0.0),
            "payment_method": _as_str(r.get("payment_method"), "unspecified"),
            "payment_reference": _as_str(r.get("payment_reference"), ""),
            "proof_url": _as_str(r.get("proof_url"), ""),
            "proof_uploaded_at": _iso(r.get("proof_uploaded_at")),
            "payment_status": _as_str(r.get("payment_status"), "unpaid"),
        }
        for r in rows
    ]


def _build_payments_summary(user_id: uuid.UUID) -> dict[str, Any]:
    """
    Build a payment-centric summary for the payments workspace.

    The response still reports refunded totals when payment rows carry that
    status, but this workspace no longer exposes active refund workflow
    mechanics.
    """
    row = _first_row(
        """
        WITH latest_payments AS (
            SELECT DISTINCT ON (p.order_id)
                p.order_id,
                COALESCE(p.amount, 0) AS amount,
                COALESCE(NULLIF(TRIM(p.status), ''), 'unpaid') AS payment_status,
                COALESCE(NULLIF(TRIM(p.method), ''), 'unspecified') AS payment_method,
                p.proof_url
            FROM payments p
            ORDER BY p.order_id, COALESCE(p.updated_at, p.created_at) DESC, p.payment_id DESC
        )
        SELECT
            COUNT(*)::int AS total_orders,
            COUNT(*) FILTER (WHERE LOWER(COALESCE(lp.payment_status, '')) = 'paid')::int AS paid_orders,
            COUNT(*) FILTER (WHERE LOWER(COALESCE(lp.payment_status, '')) = 'pending')::int AS pending_orders,
            COUNT(*) FILTER (WHERE LOWER(COALESCE(lp.payment_status, '')) = 'unpaid')::int AS unpaid_orders,
            COUNT(*) FILTER (WHERE LOWER(COALESCE(lp.payment_status, '')) = 'refunded')::int AS refunded_orders,
            COUNT(*) FILTER (WHERE TRIM(COALESCE(lp.proof_url, '')) <> '')::int AS proof_count,
            COALESCE(SUM(CASE WHEN LOWER(COALESCE(lp.payment_status, '')) = 'paid' THEN lp.amount ELSE 0 END), 0) AS paid_amount,
            COALESCE(SUM(CASE WHEN LOWER(COALESCE(lp.payment_status, '')) = 'refunded' THEN lp.amount ELSE 0 END), 0) AS refunded_amount
        FROM orders o
        LEFT JOIN latest_payments lp ON lp.order_id = o.order_id
        WHERE o.buyer_id = :user_id
        """,
        {"user_id": str(user_id)},
    )
    return {
        "total_orders": _as_int(row.get("total_orders"), 0),
        "paid_orders": _as_int(row.get("paid_orders"), 0),
        "pending_orders": _as_int(row.get("pending_orders"), 0),
        "unpaid_orders": _as_int(row.get("unpaid_orders"), 0),
        "refunded_orders": _as_int(row.get("refunded_orders"), 0),
        "proof_count": _as_int(row.get("proof_count"), 0),
        "paid_amount": _as_float(row.get("paid_amount"), 0.0),
        "refunded_amount": _as_float(row.get("refunded_amount"), 0.0),
    }


# ---------------------------------------------------------------------------
# Account builders
# ---------------------------------------------------------------------------
def _build_notification_overview(user_id: uuid.UUID) -> dict[str, Any]:
    """
    Build a customer notification overview.

    In-app notifications are live. Email/SMS toggles are still scaffolded at
    the preferences-model level.
    """
    row = _first_row(
        """
        SELECT
            COUNT(*)::int AS total_notifications,
            COUNT(*) FILTER (WHERE COALESCE(is_read, false) = false)::int AS unread_notifications,
            MAX(created_at) AS last_notification_at
        FROM notifications
        WHERE user_id = :user_id
        """,
        {"user_id": str(user_id)},
    )

    sms_row = _first_row(
        """
        SELECT
            COUNT(*)::int AS sms_total,
            MAX(COALESCE(delivered_at, sent_at, queued_at, "timestamp")) AS last_sms_at
        FROM sms_logs
        WHERE user_id = :user_id
        """,
        {"user_id": str(user_id)},
    )

    total_notifications = _as_int(row.get("total_notifications"), 0)
    unread_notifications = _as_int(row.get("unread_notifications"), 0)
    sms_total = _as_int(sms_row.get("sms_total"), 0)

    channels = [
        {
            "key": "in_app",
            "label": "In-app alerts",
            "enabled": True,
            "configurable": False,
            "status": "live",
            "description": "Order, payment, and workflow events already surface through the notifications center.",
            "last_event_at": _iso(row.get("last_notification_at")),
        },
        {
            "key": "email",
            "label": "Email notifications",
            "enabled": False,
            "configurable": False,
            "status": "scaffolded",
            "description": "Preference persistence is planned for the next customer preference model.",
            "last_event_at": None,
        },
        {
            "key": "sms",
            "label": "SMS notifications",
            "enabled": sms_total > 0,
            "configurable": False,
            "status": "scaffolded",
            "description": "SMS evidence exists in the communication ledger, but customer-level toggle management is not yet persisted.",
            "last_event_at": _iso(sms_row.get("last_sms_at")),
        },
    ]

    return {
        "total_notifications": total_notifications,
        "unread_notifications": unread_notifications,
        "last_notification_at": _iso(row.get("last_notification_at")),
        "preferences_model_ready": False,
        "in_app_available": True,
        "email_preferences_ready": False,
        "sms_preferences_ready": False,
        "channels": channels,
        "delivery_summary": {
            "in_app_events": total_notifications,
            "sms_events": sms_total,
        },
    }


def _build_activity_log(user_id: uuid.UUID, limit: int = 16) -> list[dict[str, Any]]:
    """Return customer account activity from route and session events."""
    rows = _run_query(
        """
        SELECT *
        FROM (
            SELECT
                'activity' AS source,
                COALESCE(NULLIF(TRIM(ua.action), ''), 'activity') AS action,
                COALESCE(NULLIF(TRIM(ua.route), ''), '') AS route,
                COALESCE(NULLIF(TRIM(ua.status), ''), 'success') AS status,
                ua.occurred_at AS happened_at,
                COALESCE(NULLIF(TRIM(ua.target_type), ''), '') AS target_type,
                COALESCE(ua.target_id::text, '') AS target_id,
                COALESCE(NULLIF(TRIM(ua.http_method), ''), '') AS http_method
            FROM user_activity_events ua
            WHERE ua.user_id = :user_id

            UNION ALL

            SELECT
                'session' AS source,
                COALESCE(NULLIF(TRIM(le.event_type), ''), 'session') AS action,
                '' AS route,
                'success' AS status,
                le.created_at AS happened_at,
                '' AS target_type,
                '' AS target_id,
                '' AS http_method
            FROM login_events le
            WHERE le.user_id = :user_id
        ) combined
        ORDER BY happened_at DESC
        LIMIT :limit
        """,
        {"user_id": str(user_id), "limit": max(10, min(_as_int(limit, 16), 40))},
    )
    return [
        {
            "source": _as_str(r.get("source"), "activity"),
            "action": _as_str(r.get("action"), "activity"),
            "route": _as_str(r.get("route"), ""),
            "status": _as_str(r.get("status"), "success"),
            "happened_at": _iso(r.get("happened_at")),
            "target_type": _as_str(r.get("target_type"), ""),
            "target_id": _as_str(r.get("target_id"), ""),
            "http_method": _as_str(r.get("http_method"), ""),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@customer_workspace_bp.get("/saved-search")
@customer_workspace_bp.get("/saved_and_search")
@require_auth("customer")
def get_saved_search_workspace() -> Any:
    """Customer saved/search workspace."""
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"success": False, "message": "Invalid user."}), 401

    recent_searches = _build_recent_searches(user_id)
    liked_products = _build_liked_products(user_id)
    recently_viewed = _build_recently_viewed(user_id)
    repeat_purchases = _build_repeat_purchases(user_id)
    funnel = _build_behavior_funnel(user_id)

    notes: list[str] = []
    if recent_searches:
        notes.append(
            f"You have {len(recent_searches)} recent search signal(s) available for discovery memory."
        )
    if liked_products:
        notes.append(
            f"You currently maintain {len(liked_products)} liked product(s) that can drive personalized recommendations."
        )
    if recently_viewed:
        notes.append(
            f"Recently viewed activity is available across {len(recently_viewed)} product(s)."
        )
    if repeat_purchases:
        notes.append(
            f"Repeat purchase history already highlights {len(repeat_purchases)} reorder candidate product(s)."
        )
    if not notes:
        notes.append(
            "Saved and discovery intelligence will strengthen as the customer searches, views, likes, and reorders products."
        )

    return jsonify(
        {
            "success": True,
            "summary": {
                "searches_count": funnel.get("searched", 0),
                "viewed_count": funnel.get("viewed", 0),
                "likes_count": len(liked_products),
                "repeat_products_count": len(repeat_purchases),
            },
            "recent_searches": recent_searches,
            "liked_products": liked_products,
            "recently_viewed": recently_viewed,
            "repeat_purchases": repeat_purchases,
            "behavior_funnel": funnel,
            "notes": notes[:4],
        }
    ), 200


@customer_workspace_bp.get("/payments")
@customer_workspace_bp.get("/payments/summary")
@require_auth("customer")
def get_customer_payments_workspace() -> Any:
    """Customer payments workspace with summary, history, and proof archive."""
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"success": False, "message": "Invalid user."}), 401

    summary = _build_payments_summary(user_id)
    payment_methods_used = _build_payment_methods_used(user_id)
    payment_history = _build_payment_history(user_id)
    proof_archive = _build_proof_archive(user_id)

    notes: list[str] = []

    if _as_float(summary.get("paid_amount"), 0.0) > 0:
        notes.append(
            f"Paid order value currently totals N$ {_as_float(summary.get('paid_amount'), 0.0):.2f}."
        )

    if _as_int(summary.get("proof_count"), 0) > 0:
        notes.append(
            f"Proof-of-payment evidence exists for {_as_int(summary.get('proof_count'), 0)} payment record(s)."
        )

    if _as_int(summary.get("pending_orders"), 0) > 0:
        notes.append(
            f"{_as_int(summary.get('pending_orders'), 0)} payment record(s) are still pending confirmation."
        )

    if not notes:
        notes.append(
            "Payment history and proof-of-payment visibility will expand as more checkout activity is recorded."
        )

    return (
        jsonify(
            {
                "success": True,
                "summary": summary,
                "payment_methods_used": payment_methods_used,
                "payment_history": payment_history,
                "proof_archive": proof_archive,
                "notes": notes,
            }
        ),
        200,
    )


@customer_workspace_bp.get("/account")
@require_auth("customer")
def get_customer_account_workspace() -> Any:
    """Customer account workspace limited to profile, notifications, and privacy context."""
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"success": False, "message": "Invalid user."}), 401

    user_payload = _current_user_dict()
    notification_overview = _build_notification_overview(user_id)
    activity_log = _build_activity_log(user_id)

    profile = {
        "id": _as_str(user_payload.get("id"), str(user_id)),
        "full_name": _as_str(user_payload.get("full_name"), ""),
        "phone": _as_str(user_payload.get("phone"), ""),
        "email": _as_str(user_payload.get("email"), ""),
        "location": _as_str(user_payload.get("location"), ""),
        "role": _as_int(user_payload.get("role"), 3),
        "created_at": _iso(user_payload.get("created_at")),
        "updated_at": _iso(user_payload.get("updated_at")),
        "last_login_at": _iso(user_payload.get("last_login_at")),
        "last_seen_at": _iso(user_payload.get("last_seen_at")),
    }

    account_notes = [
        "Personal details can be updated immediately and are shared with delivery and support workflows.",
        "In-app notifications are already operational, while persisted email and SMS preference controls require the planned customer preference model.",
        "Activity history already captures session and route-level customer actions for privacy transparency.",
        "Addresses and support ticketing are intentionally scaffolded so the account workspace can expand cleanly when Phase-2 tables are introduced.",
    ]

    addresses = {
        "enabled": False,
        "count": 0,
        "primary_label": "Default delivery area",
        "primary_text": _as_str(profile.get("location"), "No saved address yet"),
        "placeholder_items": [
            {
                "label": "Primary delivery address",
                "status": "placeholder",
                "line1": _as_str(
                    profile.get("location"),
                    "Customer location is currently stored only at profile level.",
                ),
            },
            {
                "label": "Secondary address",
                "status": "placeholder",
                "line1": "Saved addresses will become available after the customer_addresses table is introduced.",
            },
        ],
        "notes": [
            "Saved addresses require the customer_addresses table planned for Phase 2.",
            "The current profile location can still guide delivery coordination in the meantime.",
        ],
    }

    support = {
        "tickets_enabled": False,
        "primary_channel": "In-app notifications + manual admin follow-up",
        "response_sla_hours": 72,
        "channels": [
            {
                "name": "In-app follow-up",
                "status": "live",
                "description": "Order and payment events already reach the customer through the notifications center.",
            },
            {
                "name": "Ticketing workflow",
                "status": "planned",
                "description": "Dedicated customer support tickets are recommended for the next backend phase.",
            },
            {
                "name": "Order issue workflow",
                "status": "planned",
                "description": "Structured order issues and dispute handling are deferred as a future feature.",
            },
        ],
        "notes": [
            "Customer support tickets are recommended for the next backend phase.",
            "Order issues, disputes, and refund resolution remain deferred for a later system feature.",
        ],
    }

    privacy = {
        "activity_log_ready": True,
        "preferences_model_ready": False,
        "records_visible": len(activity_log),
        "last_seen_at": profile.get("last_seen_at"),
        "last_login_at": profile.get("last_login_at"),
        "notes": [
            "Activity visibility is live from login events and user activity events.",
            "Dedicated privacy preferences and retention controls require a future preferences model.",
        ],
    }

    payment_overview = {
        "ready": True,
        "workspace_route": "/dashboard/customer/payments",
        "notes": [
            "Payment history and proof-of-payment visibility remain available.",
            "Refund and dispute workflow is deferred as a future system feature.",
        ],
    }

    return (
        jsonify(
            {
                "success": True,
                "profile": profile,
                "notification_overview": notification_overview,
                "payment_overview": payment_overview,
                "activity_log": activity_log,
                "addresses": addresses,
                "support": support,
                "privacy": privacy,
                "notes": account_notes,
            }
        ),
        200,
    )