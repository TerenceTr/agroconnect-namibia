# ====================================================================
# backend/routes/admin_analytics.py — Admin Analytics Summary (JWT)
# --------------------------------------------------------------------
# FILE ROLE:
#   Professional admin analytics feed for governance, monitoring,
#   product moderation, live presence, notifications, and demand outlook.
#
# ROUTES (url_prefix="/api/admin"):
#   GET /api/admin/analytics/summary
#   GET /api/admin/analytics     (alias)
#
# THIS UPDATE:
#   ✅ Keeps the raw analytics payload available for compatibility
#   ✅ Adds executive doughnut-chart distributions for orders/products
#   ✅ Fixes brittle online-user parsing across presence providers
#   ✅ Makes the notification watchlist useful even when direct admin
#      notifications are sparse by falling back to recent moderation events
#   ✅ Returns UTC-aware timestamps + epoch milliseconds for stable frontend timing
# ====================================================================

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime, timedelta, timezone
from typing import Any, Optional, cast

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response

from sqlalchemy import inspect, text

from backend.database.db import db
from backend.models.user import ROLE_ADMIN, User
from backend.services.presence_store import snapshot as memory_presence_snapshot
from backend.utils.require_auth import require_access_token

admin_analytics_bp = Blueprint("admin_analytics", __name__)

ROLE_FARMER = 2
ROLE_CUSTOMER = 3

ONLINE_WINDOW_MINUTES = 10
RECENT_WINDOW_HOURS = 24
DEFAULT_WINDOW_DAYS = 30
MAX_TOP_PRODUCTS = 6
MAX_DEMAND_ROWS = 8
MAX_RECENT_PRODUCTS = 8
MAX_NOTIFICATIONS = 8
MAX_PRESENCE_ROWS = 8
MAX_FALLBACK_ALERTS = 12


# --------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------
def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return cast(Response, resp)


def _current_user() -> Optional[User]:
    u = getattr(g, "current_user", None)
    if isinstance(u, User):
        return u

    u2 = getattr(request, "current_user", None)
    if isinstance(u2, User):
        return u2

    return None


def _admin_guard() -> Optional[Response]:
    u = _current_user()
    if u is None:
        return _json({"success": False, "message": "Authentication required"}, 401)

    if int(getattr(u, "role", 0) or 0) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)

    return None


def _table_exists(table_name: str) -> bool:
    try:
        bind = db.session.get_bind()
        inspector = inspect(bind)
        return table_name in set(inspector.get_table_names() or [])
    except Exception:
        return False


def _as_utc_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    return None


def _safe_iso(value: Any) -> Optional[str]:
    if value is None:
        return None

    dt = _as_utc_datetime(value)
    if dt is not None:
        return dt.isoformat().replace("+00:00", "Z")

    try:
        return str(value)
    except Exception:
        return None


def _safe_epoch_ms(value: Any) -> Optional[int]:
    dt = _as_utc_datetime(value)
    if dt is None:
        return None

    try:
        return int(dt.timestamp() * 1000)
    except Exception:
        return None


def _safe_float(value: Any, fallback: float = 0.0) -> float:
    try:
        return float(value or 0.0)
    except Exception:
        return fallback


def _safe_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value or 0)
    except Exception:
        return fallback


def _safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback

    try:
        s = str(value).strip()
        return s if s else fallback
    except Exception:
        return fallback


def _is_non_string_iterable(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (str, bytes, bytearray)):
        return False
    if isinstance(value, Mapping):
        return False
    if isinstance(value, (int, float, bool)):
        return False
    return isinstance(value, Iterable)


def _extract_ids_from_sequence(value: Any) -> set[str]:
    out: set[str] = set()

    if not _is_non_string_iterable(value):
        return out

    try:
        for item in cast(Iterable[Any], value):
            if isinstance(item, (str, bytes, bytearray)):
                uid = _safe_str(item)
                if uid:
                    out.add(uid)
                continue

            if isinstance(item, Mapping):
                uid = (
                    _safe_str(item.get("user_id"))
                    or _safe_str(item.get("id"))
                    or _safe_str(item.get("uid"))
                )
                if uid:
                    out.add(uid)
                continue

            if isinstance(item, (int, float, bool)):
                continue

            uid = _safe_str(item)
            if uid:
                out.add(uid)
    except Exception:
        return out

    return out


def _extract_ids_from_presence_snapshot(snapshot_payload: Any) -> set[str]:
    live_ids: set[str] = set()

    if _is_non_string_iterable(snapshot_payload):
        live_ids.update(_extract_ids_from_sequence(snapshot_payload))
        return live_ids

    if isinstance(snapshot_payload, Mapping):
        for key in (
            "active",
            "active_ids",
            "online",
            "online_ids",
            "user_ids",
            "users",
            "members",
            "connections",
        ):
            if key not in snapshot_payload:
                continue
            live_ids.update(_extract_ids_from_sequence(snapshot_payload.get(key)))

    return live_ids


# --------------------------------------------------------------------
# Query blocks — counts and distributions
# --------------------------------------------------------------------
def _orders_by_status_raw(window_days: int) -> tuple[dict[str, int], dict[str, int]]:
    orders_by_status: dict[str, int] = {}
    orders_by_status_window: dict[str, int] = {}

    if not _table_exists("orders"):
        return orders_by_status, orders_by_status_window

    try:
        rows = db.session.execute(
            text(
                """
                SELECT COALESCE(LOWER(status), 'unknown') AS status, COUNT(*) AS count
                FROM orders
                GROUP BY COALESCE(LOWER(status), 'unknown')
                ORDER BY 1
                """
            )
        ).all()
        orders_by_status = {str(status): _safe_int(count) for status, count in rows}
    except Exception:
        orders_by_status = {}

    since_dt = datetime.utcnow() - timedelta(days=window_days)
    try:
        rows = db.session.execute(
            text(
                """
                SELECT COALESCE(LOWER(status), 'unknown') AS status, COUNT(*) AS count
                FROM orders
                WHERE order_date >= :since_dt
                GROUP BY COALESCE(LOWER(status), 'unknown')
                ORDER BY 1
                """
            ),
            {"since_dt": since_dt},
        ).all()
        orders_by_status_window = {str(status): _safe_int(count) for status, count in rows}
    except Exception:
        orders_by_status_window = {}

    return orders_by_status, orders_by_status_window


def _orders_status_distribution() -> dict[str, int]:
    """
    Executive operational distribution used by the doughnut chart.

    Logic:
      - delivered: delivery_status='delivered' OR delivered_at present
      - completed: completed but not yet delivered
      - pending: every remaining operational order state

    This intentionally collapses lower-level raw states into three clear buckets.
    """
    if not _table_exists("orders"):
        return {"pending": 0, "completed": 0, "delivered": 0}

    try:
        rows = db.session.execute(
            text(
                """
                SELECT bucket, COUNT(*) AS count
                FROM (
                    SELECT
                        CASE
                            WHEN COALESCE(LOWER(delivery_status), 'pending') = 'delivered'
                                 OR delivered_at IS NOT NULL THEN 'delivered'
                            WHEN COALESCE(LOWER(status), 'pending') = 'completed' THEN 'completed'
                            ELSE 'pending'
                        END AS bucket
                    FROM orders
                ) ranked
                GROUP BY bucket
                ORDER BY bucket
                """
            )
        ).all()
        out = {str(bucket): _safe_int(count) for bucket, count in rows}
        return {
            "pending": _safe_int(out.get("pending")),
            "completed": _safe_int(out.get("completed")),
            "delivered": _safe_int(out.get("delivered")),
        }
    except Exception:
        return {"pending": 0, "completed": 0, "delivered": 0}


def _products_by_status_raw() -> dict[str, int]:
    if not _table_exists("products"):
        return {}

    try:
        rows = db.session.execute(
            text(
                """
                SELECT COALESCE(LOWER(status), 'unknown') AS status, COUNT(*) AS count
                FROM products
                GROUP BY COALESCE(LOWER(status), 'unknown')
                ORDER BY 1
                """
            )
        ).all()
        return {str(status): _safe_int(count) for status, count in rows}
    except Exception:
        return {}


def _products_status_distribution() -> dict[str, int]:
    """
    Executive catalogue-governance distribution used by the doughnut chart.

    Mapping:
      - available: available / approved / active / published
      - rejected: rejected
      - pending: all remaining listing states
    """
    if not _table_exists("products"):
        return {"pending": 0, "available": 0, "rejected": 0}

    try:
        rows = db.session.execute(
            text(
                """
                SELECT bucket, COUNT(*) AS count
                FROM (
                    SELECT
                        CASE
                            WHEN COALESCE(LOWER(status), 'pending') IN ('available', 'approved', 'active', 'published')
                                THEN 'available'
                            WHEN COALESCE(LOWER(status), 'pending') = 'rejected'
                                THEN 'rejected'
                            ELSE 'pending'
                        END AS bucket
                    FROM products
                ) ranked
                GROUP BY bucket
                ORDER BY bucket
                """
            )
        ).all()
        out = {str(bucket): _safe_int(count) for bucket, count in rows}
        return {
            "pending": _safe_int(out.get("pending")),
            "available": _safe_int(out.get("available")),
            "rejected": _safe_int(out.get("rejected")),
        }
    except Exception:
        return {"pending": 0, "available": 0, "rejected": 0}


def _ratings_summary(window_days: int) -> tuple[float, list[dict[str, Any]]]:
    avg_rating = 0.0
    ratings_trend: list[dict[str, Any]] = []

    if not _table_exists("ratings"):
        return avg_rating, ratings_trend

    since_dt = datetime.utcnow() - timedelta(days=window_days)

    try:
        avg_val = db.session.execute(text("SELECT AVG(rating_score) FROM ratings")).scalar()
        avg_rating = _safe_float(avg_val)
    except Exception:
        avg_rating = 0.0

    try:
        rows = db.session.execute(
            text(
                """
                SELECT DATE(created_at) AS day, COUNT(*) AS count, AVG(rating_score) AS avg
                FROM ratings
                WHERE created_at >= :since_dt
                GROUP BY DATE(created_at)
                ORDER BY DATE(created_at)
                """
            ),
            {"since_dt": since_dt},
        ).all()

        ratings_trend = [
            {
                "date": _safe_iso(day) or str(day),
                "count": _safe_int(count),
                "avg": _safe_float(avg),
            }
            for day, count, avg in rows
        ]
    except Exception:
        ratings_trend = []

    return avg_rating, ratings_trend


def _top_products() -> list[dict[str, Any]]:
    if not _table_exists("order_items") or not _table_exists("products") or not _table_exists("orders"):
        return []

    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    p.product_id,
                    p.product_name,
                    p.category,
                    COUNT(DISTINCT oi.order_id) AS order_count,
                    COALESCE(SUM(oi.line_total), 0) AS revenue
                FROM order_items oi
                JOIN products p ON p.product_id = oi.product_id
                JOIN orders o ON o.order_id = oi.order_id
                WHERE COALESCE(LOWER(o.status), 'pending') <> 'cancelled'
                GROUP BY p.product_id, p.product_name, p.category
                ORDER BY COUNT(DISTINCT oi.order_id) DESC,
                         COALESCE(SUM(oi.line_total), 0) DESC,
                         p.product_name ASC
                LIMIT :limit
                """
            ),
            {"limit": MAX_TOP_PRODUCTS},
        ).mappings().all()

        return [
            {
                "product_id": _safe_str(r.get("product_id")),
                "name": _safe_str(r.get("product_name"), "Product"),
                "category": _safe_str(r.get("category"), "—"),
                "orders": _safe_int(r.get("order_count")),
                "revenue": _safe_float(r.get("revenue")),
            }
            for r in rows
        ]
    except Exception:
        return []


def _recent_product_listings() -> list[dict[str, Any]]:
    if not _table_exists("products") or not _table_exists("users"):
        return []

    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    p.product_id,
                    p.product_name,
                    p.category,
                    p.status,
                    p.price,
                    p.quantity,
                    COALESCE(p.submitted_at, p.status_updated_at, p.created_at) AS activity_at,
                    p.rejection_reason,
                    u.id AS farmer_id,
                    u.full_name AS farmer_name,
                    u.location AS farmer_location
                FROM products p
                JOIN users u ON u.id = p.user_id
                ORDER BY
                    CASE WHEN COALESCE(LOWER(p.status), 'pending') = 'pending' THEN 0 ELSE 1 END,
                    COALESCE(p.submitted_at, p.status_updated_at, p.created_at) DESC
                LIMIT :limit
                """
            ),
            {"limit": MAX_RECENT_PRODUCTS},
        ).mappings().all()

        return [
            {
                "product_id": _safe_str(r.get("product_id")),
                "product_name": _safe_str(r.get("product_name"), "Product"),
                "category": _safe_str(r.get("category"), "—"),
                "status": _safe_str(r.get("status"), "pending").lower(),
                "price": _safe_float(r.get("price")),
                "quantity": _safe_float(r.get("quantity")),
                "activity_at": _safe_iso(r.get("activity_at")),
                "activity_epoch_ms": _safe_epoch_ms(r.get("activity_at")),
                "rejection_reason": _safe_str(r.get("rejection_reason")),
                "farmer_id": _safe_str(r.get("farmer_id")),
                "farmer_name": _safe_str(r.get("farmer_name"), "Farmer"),
                "farmer_location": _safe_str(r.get("farmer_location"), "—"),
            }
            for r in rows
        ]
    except Exception:
        return []


# --------------------------------------------------------------------
# Presence
# --------------------------------------------------------------------
def _all_presence_candidates_for_role(role: int) -> list[dict[str, Any]]:
    if not _table_exists("users"):
        return []

    try:
        if _table_exists("login_events"):
            query = text(
                """
                WITH seen AS (
                    SELECT
                        u.id,
                        u.full_name,
                        u.email,
                        u.location,
                        u.role,
                        GREATEST(
                            COALESCE(u.last_seen_at, TIMESTAMP '1970-01-01'),
                            COALESCE(MAX(le.created_at AT TIME ZONE 'UTC'), TIMESTAMP '1970-01-01')
                        ) AS last_seen
                    FROM users u
                    LEFT JOIN login_events le ON le.user_id = u.id
                    WHERE u.role = :role
                      AND COALESCE(u.is_active, TRUE) = TRUE
                    GROUP BY u.id, u.full_name, u.email, u.location, u.role, u.last_seen_at
                )
                SELECT id, full_name, email, location, role, last_seen
                FROM seen
                ORDER BY last_seen DESC, full_name ASC
                LIMIT 50
                """
            )
        else:
            query = text(
                """
                SELECT
                    u.id,
                    u.full_name,
                    u.email,
                    u.location,
                    u.role,
                    COALESCE(u.last_seen_at, TIMESTAMP '1970-01-01') AS last_seen
                FROM users u
                WHERE u.role = :role
                  AND COALESCE(u.is_active, TRUE) = TRUE
                ORDER BY COALESCE(u.last_seen_at, TIMESTAMP '1970-01-01') DESC, u.full_name ASC
                LIMIT 50
                """
            )

        rows = db.session.execute(query, {"role": role}).mappings().all()

        out: list[dict[str, Any]] = []
        for r in rows:
            last_seen = r.get("last_seen")
            out.append(
                {
                    "user_id": _safe_str(r.get("id")),
                    "full_name": _safe_str(r.get("full_name"), "User"),
                    "email": _safe_str(r.get("email"), "—"),
                    "location": _safe_str(r.get("location"), "—"),
                    "role": _safe_int(r.get("role")),
                    "last_seen_at": _safe_iso(last_seen),
                    "last_seen_epoch_ms": _safe_epoch_ms(last_seen),
                }
            )
        return out
    except Exception:
        return []


def _live_online_ids() -> set[str]:
    online_ids: set[str] = set()

    try:
        from backend.utils.presence import presence_snapshot as redis_presence_snapshot

        snap = redis_presence_snapshot()
        online_ids.update(_extract_ids_from_presence_snapshot(snap))
    except Exception:
        pass

    try:
        mem = memory_presence_snapshot()
        if isinstance(mem, tuple) and len(mem) >= 2:
            online_ids.update(_extract_ids_from_presence_snapshot(mem[1]))
        else:
            online_ids.update(_extract_ids_from_presence_snapshot(mem))
    except Exception:
        pass

    return online_ids


def _presence_partition(role: int, live_ids: set[str]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = _all_presence_candidates_for_role(role)
    recent_cutoff_ms = int(
        (datetime.utcnow() - timedelta(hours=RECENT_WINDOW_HOURS)).timestamp() * 1000
    )

    online: list[dict[str, Any]] = []
    recent: list[dict[str, Any]] = []

    for row in rows:
        uid = _safe_str(row.get("user_id"))
        last_seen_ms = _safe_int(row.get("last_seen_epoch_ms"), 0)
        is_online = bool(uid and uid in live_ids)
        enriched = {**row, "is_online": is_online}

        if is_online:
            online.append(enriched)
        elif last_seen_ms > 0 and last_seen_ms >= recent_cutoff_ms:
            recent.append(enriched)

    return online[:MAX_PRESENCE_ROWS], recent[:MAX_PRESENCE_ROWS]


def _presence_summary() -> dict[str, Any]:
    live_ids = _live_online_ids()
    farmers_online, farmers_recent = _presence_partition(ROLE_FARMER, live_ids)
    customers_online, customers_recent = _presence_partition(ROLE_CUSTOMER, live_ids)

    server_now = datetime.now(timezone.utc)

    return {
        "window_minutes": ONLINE_WINDOW_MINUTES,
        "server_now_utc": server_now.isoformat().replace("+00:00", "Z"),
        "server_now_epoch_ms": int(server_now.timestamp() * 1000),
        "farmers_count": len(farmers_online),
        "customers_count": len(customers_online),
        "farmers_online": farmers_online,
        "customers_online": customers_online,
        "farmers_recent": farmers_recent,
        "customers_recent": customers_recent,
    }


# --------------------------------------------------------------------
# Notifications / watchlist
# --------------------------------------------------------------------
def _build_moderation_fallback_alerts(limit: int = MAX_FALLBACK_ALERTS) -> list[dict[str, Any]]:
    """
    Fallback admin watchlist when direct admin notifications are empty.

    Source priority:
      1) product_moderation_events (workflow events such as submitted / edited / rejected)
      2) currently rejected products (so governance issues are never visually blank)
    """
    items: list[dict[str, Any]] = []

    if _table_exists("product_moderation_events"):
        try:
            rows = db.session.execute(
                text(
                    """
                    SELECT
                        e.id AS event_id,
                        e.product_id,
                        LOWER(COALESCE(e.action, 'submitted')) AS action,
                        LOWER(COALESCE(e.actor_role, 'farmer')) AS actor_role,
                        e.actor_id,
                        e.created_at,
                        e.notes,
                        p.product_name,
                        p.status AS product_status,
                        p.rejection_reason,
                        u.full_name AS actor_name
                    FROM product_moderation_events e
                    LEFT JOIN products p ON CAST(p.product_id AS text) = e.product_id
                    LEFT JOIN users u ON CAST(u.id AS text) = e.actor_id
                    ORDER BY e.created_at DESC
                    LIMIT :limit
                    """
                ),
                {"limit": limit},
            ).mappings().all()

            for r in rows:
                action = _safe_str(r.get("action"), "submitted").lower()
                actor_role = _safe_str(r.get("actor_role"), "farmer").lower()
                product_name = _safe_str(r.get("product_name"), "Product")
                actor_name = _safe_str(r.get("actor_name"), "User")
                created_at = r.get("created_at")
                rejection_reason = _safe_str(r.get("rejection_reason"))
                notes = _safe_str(r.get("notes"))
                event_id = _safe_str(r.get("event_id"))
                product_id = _safe_str(r.get("product_id"))

                if action in {"submitted", "resubmitted"}:
                    title = "Listing submitted for review"
                    message = f"{actor_name} submitted {product_name} for governance review."
                    alert_type = "product_submission"
                elif action in {"edited", "updated"} and actor_role == "farmer":
                    title = "Listing updated by farmer"
                    message = f"{actor_name} updated {product_name}. Review the latest listing changes."
                    alert_type = "product_update"
                elif action == "rejected":
                    detail = rejection_reason or notes or "A rejection reason was recorded."
                    title = "Listing rejected"
                    message = f"{product_name} is currently rejected. {detail}"
                    alert_type = "product_rejected"
                elif action == "approved":
                    title = "Listing approved"
                    message = f"{product_name} was approved and published."
                    alert_type = "product_approved"
                else:
                    title = "Product workflow event"
                    message = f"{product_name}: {title_case(action)}"
                    alert_type = "product_event"

                items.append(
                    {
                        "notification_id": event_id or f"moderation:{product_id}:{action}",
                        "type": alert_type,
                        "title": title,
                        "message": message,
                        "event_key": f"moderation:{product_id}:{action}:{event_id}",
                        "order_id": "",
                        "data": {
                            "product_id": product_id,
                            "action": action,
                            "actor_role": actor_role,
                        },
                        "is_read": False,
                        "created_at": _safe_iso(created_at),
                        "created_epoch_ms": _safe_epoch_ms(created_at),
                    }
                )
        except Exception:
            items = []

    if len(items) < limit and _table_exists("products") and _table_exists("users"):
        try:
            rows = db.session.execute(
                text(
                    """
                    SELECT
                        p.product_id,
                        p.product_name,
                        p.rejection_reason,
                        p.status_updated_at,
                        p.reviewed_at,
                        u.full_name AS farmer_name
                    FROM products p
                    JOIN users u ON u.id = p.user_id
                    WHERE LOWER(COALESCE(p.status, 'pending')) = 'rejected'
                    ORDER BY COALESCE(p.status_updated_at, p.reviewed_at, p.created_at) DESC
                    LIMIT :limit
                    """
                ),
                {"limit": max(1, limit - len(items))},
            ).mappings().all()

            for r in rows:
                product_id = _safe_str(r.get("product_id"))
                title = "Rejected listing requires follow-up"
                reason = _safe_str(r.get("rejection_reason"), "Review notes were recorded.")
                farmer_name = _safe_str(r.get("farmer_name"), "Farmer")
                created_at = r.get("status_updated_at") or r.get("reviewed_at")
                items.append(
                    {
                        "notification_id": f"rejected:{product_id}",
                        "type": "product_rejected",
                        "title": title,
                        "message": f"{farmer_name}'s product {_safe_str(r.get('product_name'), 'product')} is rejected. {reason}",
                        "event_key": f"rejected:{product_id}",
                        "order_id": "",
                        "data": {"product_id": product_id},
                        "is_read": False,
                        "created_at": _safe_iso(created_at),
                        "created_epoch_ms": _safe_epoch_ms(created_at),
                    }
                )
        except Exception:
            pass

    items.sort(key=lambda x: _safe_int(x.get("created_epoch_ms"), 0), reverse=True)
    return items[:limit]


def title_case(value: str) -> str:
    return " ".join(part.capitalize() for part in _safe_str(value).replace("_", " ").split())


def _notifications_summary(admin_user_id: str) -> dict[str, Any]:
    direct_items: list[dict[str, Any]] = []
    unread_count = 0

    if admin_user_id and _table_exists("notifications"):
        try:
            unread_count_val = db.session.execute(
                text(
                    """
                    SELECT COUNT(*)
                    FROM notifications
                    WHERE (CAST(user_id AS text) = :user_id OR CAST(actor_user_id AS text) = :user_id)
                      AND COALESCE(is_read, FALSE) = FALSE
                    """
                ),
                {"user_id": admin_user_id},
            ).scalar()
            unread_count = _safe_int(unread_count_val)

            rows = db.session.execute(
                text(
                    """
                    SELECT
                        notification_id,
                        notification_type,
                        title,
                        message,
                        event_key,
                        order_id,
                        data_json,
                        is_read,
                        created_at
                    FROM notifications
                    WHERE CAST(user_id AS text) = :user_id OR CAST(actor_user_id AS text) = :user_id
                    ORDER BY created_at DESC
                    LIMIT :limit
                    """
                ),
                {"user_id": admin_user_id, "limit": MAX_NOTIFICATIONS},
            ).mappings().all()

            direct_items = [
                {
                    "notification_id": _safe_str(r.get("notification_id")),
                    "type": _safe_str(r.get("notification_type"), "system"),
                    "title": _safe_str(r.get("title"), "Notification"),
                    "message": _safe_str(r.get("message")),
                    "event_key": _safe_str(r.get("event_key")),
                    "order_id": _safe_str(r.get("order_id")) if r.get("order_id") is not None else "",
                    "data": r.get("data_json") if isinstance(r.get("data_json"), dict) else {},
                    "is_read": bool(r.get("is_read")),
                    "created_at": _safe_iso(r.get("created_at")),
                    "created_epoch_ms": _safe_epoch_ms(r.get("created_at")),
                }
                for r in rows
            ]
        except Exception:
            direct_items = []
            unread_count = 0

    fallback_items = _build_moderation_fallback_alerts(MAX_FALLBACK_ALERTS)

    merged: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    for row in [*direct_items, *fallback_items]:
        key = _safe_str(row.get("event_key")) or _safe_str(row.get("notification_id"))
        if key in seen_keys:
            continue
        seen_keys.add(key)
        merged.append(row)

    merged.sort(key=lambda x: _safe_int(x.get("created_epoch_ms"), 0), reverse=True)

    if unread_count <= 0:
        unread_count = sum(1 for row in merged if not bool(row.get("is_read")))

    return {
        "unread_count": unread_count,
        "items": merged[:MAX_NOTIFICATIONS],
    }


# --------------------------------------------------------------------
# Demand and SLA
# --------------------------------------------------------------------
def _demand_predictions() -> list[dict[str, Any]]:
    if not _table_exists("ai_prediction_logs"):
        return []

    try:
        rows = db.session.execute(
            text(
                """
                SELECT
                    l.entity_id AS product_id,
                    COALESCE(p.product_name, l.crop) AS product_name,
                    p.category,
                    u.full_name AS farmer_name,
                    u.location AS farmer_location,
                    l.task,
                    l.predicted_value,
                    l.actual_value,
                    l.model_version,
                    l.predicted_at,
                    COALESCE(NULLIF(l.meta->>'window_days', ''), '30')::int AS horizon_days
                FROM ai_prediction_logs l
                LEFT JOIN products p ON p.product_id = l.entity_id
                LEFT JOIN users u ON u.id = p.user_id
                WHERE l.task IN ('forecast', 'demand')
                ORDER BY l.predicted_at DESC, l.predicted_value DESC
                LIMIT :limit
                """
            ),
            {"limit": MAX_DEMAND_ROWS},
        ).mappings().all()

        return [
            {
                "product_id": _safe_str(r.get("product_id")),
                "product_name": _safe_str(r.get("product_name"), "Unknown product"),
                "category": _safe_str(r.get("category"), "—"),
                "farmer_name": _safe_str(r.get("farmer_name"), "—"),
                "farmer_location": _safe_str(r.get("farmer_location"), "—"),
                "task": _safe_str(r.get("task"), "forecast"),
                "predicted_value": _safe_float(r.get("predicted_value")),
                "actual_value": None if r.get("actual_value") is None else _safe_float(r.get("actual_value")),
                "model_version": _safe_str(r.get("model_version"), "—"),
                "predicted_at": _safe_iso(r.get("predicted_at")),
                "predicted_epoch_ms": _safe_epoch_ms(r.get("predicted_at")),
                "horizon_days": _safe_int(r.get("horizon_days"), 30),
            }
            for r in rows
        ]
    except Exception:
        return []


def _sla_payload(window_days: int) -> Any:
    try:
        from backend.services.sla_metrics import build_sla_payload

        return build_sla_payload(
            start_dt=datetime.utcnow() - timedelta(days=window_days),
            end_dt=datetime.utcnow(),
        )
    except Exception:
        return None


# --------------------------------------------------------------------
# Main payload
# --------------------------------------------------------------------
def _build_summary_payload() -> dict[str, Any]:
    window_days = DEFAULT_WINDOW_DAYS
    current_user = _current_user()
    admin_user_id = _safe_str(getattr(current_user, "id", "") or "")

    raw_orders_by_status, raw_orders_by_status_window = _orders_by_status_raw(window_days)
    raw_products_by_status = _products_by_status_raw()
    avg_rating, ratings_trend = _ratings_summary(window_days)

    return {
        "window_days": window_days,
        # Raw maps kept for compatibility with any existing consumers.
        "orders_by_status": raw_orders_by_status,
        "orders_by_status_window": raw_orders_by_status_window,
        "products_by_status": raw_products_by_status,
        # Executive distributions for doughnut charts.
        "orders_status_distribution": _orders_status_distribution(),
        "products_status_distribution": _products_status_distribution(),
        "avg_rating": avg_rating,
        "ratings_trend": ratings_trend,
        "top_products": _top_products(),
        "recent_products": _recent_product_listings(),
        "presence": _presence_summary(),
        "notifications": _notifications_summary(admin_user_id),
        "demand_predictions": _demand_predictions(),
        "sla": _sla_payload(window_days),
    }


# --------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------
@admin_analytics_bp.route("/analytics/summary", methods=["GET"])
@require_access_token
def summary() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard
    return _json(_build_summary_payload())


@admin_analytics_bp.route("/analytics", methods=["GET"])
@require_access_token
def summary_alias() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard
    return _json(_build_summary_payload())