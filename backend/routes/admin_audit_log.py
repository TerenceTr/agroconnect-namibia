# ============================================================================
# backend/routes/admin_audit_log.py — Unified Admin Audit + Activity API
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Powers the Admin Audit Log workspace.
#
# THIS VERSION FIXES:
#   ✅ Pyright issue: use sqlalchemy.cast(..., String()) instead of db.String
#   ✅ Pyright issue: avoid direct hard dependency on User.last_seen_at
#   ✅ Works even when optional audit/activity tables are missing
#   ✅ Uses ORM where stable, with SQL fallbacks where schema/model drift exists
#   ✅ Surfaces health / coverage metadata and insight bullets
#
# ROUTES:
#   GET /api/admin/audit-log
#   GET /api/admin/audit-log/summary
# ============================================================================
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import Select, String, and_, cast, func, inspect, or_, select, text

from backend.database.db import db
from backend.models.admin_audit_event import AdminAuditLog
from backend.models.login_event import LoginEvent
from backend.models.user import ROLE_ADMIN, User
from backend.models.user_activity_event import UserActivityEvent
from backend.utils.require_auth import require_access_token

admin_audit_bp = Blueprint("admin_audit", __name__)


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
ROLE_NAME_TO_INT = {"admin": 1, "farmer": 2, "customer": 3}
NOISY_AUTH_EVENT_TYPES = {"seen"}


# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------
def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        text_value = str(value).strip()
    except Exception:
        return None
    return text_value or None


def _as_uuid(value: Any) -> Optional[UUID]:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value).strip())
    except Exception:
        return None


def _to_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value

    raw = str(value).strip()
    if not raw:
        return None

    try:
        if raw.endswith("Z"):
            raw = raw[:-1]
        if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
            return datetime.fromisoformat(raw + "T00:00:00")
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _current_user() -> Optional[User]:
    current_user = getattr(g, "current_user", None)
    if isinstance(current_user, User):
        return current_user

    request_user = getattr(request, "current_user", None)
    if isinstance(request_user, User):
        return request_user

    return None


def _admin_guard() -> Optional[Response]:
    user = _current_user()
    if user is None:
        return _json({"success": False, "message": "Authentication required"}, 401)

    if int(getattr(user, "role", 0) or 0) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)

    return None


def _role_name_from_value(role_value: Any) -> str:
    try:
        role_int = int(role_value) if role_value is not None else 0
    except Exception:
        role_int = 0

    return {1: "admin", 2: "farmer", 3: "customer"}.get(role_int, "unknown")


def _normalize_stream(value: Any) -> str:
    raw = (str(value or "all")).strip().lower()
    return raw if raw in {"all", "governance", "activity", "auth"} else "all"


def _normalize_status(value: Any) -> Optional[str]:
    raw = _safe_str(value)
    return raw.lower() if raw else None


def _normalize_role_filter(value: Any) -> Optional[str]:
    raw = _safe_str(value)
    if not raw:
        return None
    lowered = raw.lower()
    return lowered if lowered in {"admin", "farmer", "customer"} else None


def _date_range_from_request() -> tuple[Optional[datetime], Optional[datetime], int]:
    """
    Supported query params:
      from=2026-04-01
      to=2026-04-04
      days=30
    """
    from_dt = _parse_dt(request.args.get("from") or request.args.get("start"))
    to_dt = _parse_dt(request.args.get("to") or request.args.get("end"))
    days = _to_int(request.args.get("days"), 0)

    if from_dt or to_dt:
        return from_dt, to_dt, max(0, days)

    if days > 0:
        end_dt = datetime.utcnow()
        start_dt = end_dt - timedelta(days=max(1, min(days, 3650)))
        return start_dt, end_dt, days

    return None, None, 0


def _apply_time_filters(stmt: Select[Any], col: Any) -> Select[Any]:
    from_dt, to_dt, _days = _date_range_from_request()
    if from_dt is not None:
        stmt = stmt.where(col >= from_dt)
    if to_dt is not None:
        stmt = stmt.where(col <= to_dt)
    return stmt


def _table_exists(table_name: str) -> bool:
    try:
        return bool(inspect(db.engine).has_table(table_name))
    except Exception:
        return False


def _limit_and_offset() -> tuple[int, int]:
    limit = max(1, min(_to_int(request.args.get("limit"), 100), 500))
    offset = max(0, _to_int(request.args.get("offset"), 0))
    return limit, offset


def _filter_context() -> dict[str, Any]:
    q = _safe_str(request.args.get("q"))
    action = _safe_str(request.args.get("action") or request.args.get("event_type"))
    actor_id = _as_uuid(
        request.args.get("actor_id")
        or request.args.get("user_id")
        or request.args.get("admin_id")
    )
    role = _normalize_role_filter(request.args.get("role"))
    status = _normalize_status(request.args.get("status"))
    target_type = _safe_str(request.args.get("target_type") or request.args.get("entity_type"))

    return {
        "q": q,
        "action": action,
        "actor_id": actor_id,
        "role": role,
        "status": status,
        "target_type": target_type,
    }


def _user_attr(name: str) -> Any:
    """
    Small helper for optional ORM attributes.

    This keeps Pyright happy when the database column exists but the SQLAlchemy
    model has not yet been updated with the mapped attribute.
    """
    return getattr(User, name, None)


def _user_display_cols() -> tuple[Any, Any]:
    """
    Keep these as Any so Pyright does not over-constrain SQLAlchemy expression use.
    """
    full_name_col: Any = _user_attr("full_name")
    email_col: Any = _user_attr("email")
    return full_name_col, email_col


# ----------------------------------------------------------------------------
# Unified row normalizers
# ----------------------------------------------------------------------------
def _governance_row_to_dict(row: Any) -> dict[str, Any]:
    audit_row, actor_name, actor_email = row
    metadata_payload = (
        getattr(audit_row, "metadata_json", None)
        or getattr(audit_row, "metadata", None)
        or {}
    )

    return {
        "stream": "governance",
        "id": str(audit_row.id),
        "occurred_at": audit_row.created_at.isoformat() if audit_row.created_at else None,
        "actor_id": str(audit_row.admin_id),
        "actor_name": actor_name,
        "actor_email": actor_email,
        "actor_role": "admin",
        "action": audit_row.action,
        "target_type": audit_row.entity_type,
        "target_id": str(audit_row.entity_id) if audit_row.entity_id else None,
        "status": "success",
        "route": None,
        "http_method": None,
        "ip_address": None,
        "user_agent": None,
        "metadata": metadata_payload,
        "source_table": "admin_audit_log",
    }


def _activity_row_to_dict(row: Any) -> dict[str, Any]:
    activity_row, actor_name, actor_email, actor_role_int = row
    return {
        "stream": "activity",
        "id": str(activity_row.event_id),
        "occurred_at": activity_row.occurred_at.isoformat() if activity_row.occurred_at else None,
        "actor_id": str(activity_row.user_id),
        "actor_name": actor_name,
        "actor_email": actor_email,
        "actor_role": activity_row.role_name or _role_name_from_value(actor_role_int),
        "action": activity_row.action,
        "target_type": activity_row.target_type,
        "target_id": str(activity_row.target_id) if activity_row.target_id else None,
        "status": activity_row.status,
        "route": activity_row.route,
        "http_method": activity_row.http_method,
        "ip_address": activity_row.ip_address,
        "user_agent": activity_row.user_agent,
        "metadata": activity_row.metadata_json or {},
        "error_message": activity_row.error_message,
        "source_table": "user_activity_events",
    }


def _auth_row_to_dict(row: Any) -> dict[str, Any]:
    auth_row, actor_name, actor_email, actor_role_int = row
    event_type = _safe_str(auth_row.event_type) or "auth_event"

    return {
        "stream": "auth",
        "id": str(auth_row.id),
        "occurred_at": auth_row.created_at.isoformat() if auth_row.created_at else None,
        "actor_id": str(auth_row.user_id),
        "actor_name": actor_name,
        "actor_email": actor_email,
        "actor_role": _role_name_from_value(actor_role_int),
        "action": event_type,
        "target_type": "session",
        "target_id": None,
        "status": "failed" if event_type == "failed_login" else "success",
        "route": None,
        "http_method": None,
        "ip_address": auth_row.ip_address,
        "user_agent": auth_row.user_agent,
        "metadata": {},
        "source_table": "login_events",
    }


# ----------------------------------------------------------------------------
# ORM query builders
# ----------------------------------------------------------------------------
def _build_governance_query() -> Select[Any]:
    ctx = _filter_context()
    full_name_col, email_col = _user_display_cols()

    stmt = (
        select(AdminAuditLog, full_name_col, email_col)
        .outerjoin(User, User.id == AdminAuditLog.admin_id)
    )
    stmt = _apply_time_filters(stmt, AdminAuditLog.created_at)

    if ctx["action"]:
        stmt = stmt.where(AdminAuditLog.action == ctx["action"])
    if ctx["target_type"]:
        stmt = stmt.where(AdminAuditLog.entity_type == ctx["target_type"])
    if ctx["actor_id"]:
        stmt = stmt.where(AdminAuditLog.admin_id == ctx["actor_id"])

    if ctx["q"]:
        like = f"%{ctx['q']}%"
        entity_id_as_text = cast(AdminAuditLog.entity_id, String())

        stmt = stmt.where(
            or_(
                AdminAuditLog.action.ilike(like),
                AdminAuditLog.entity_type.ilike(like),
                entity_id_as_text.ilike(like),
                full_name_col.ilike(like),
                email_col.ilike(like),
            )
        )

    return stmt


def _build_activity_query() -> Select[Any]:
    ctx = _filter_context()
    full_name_col, email_col = _user_display_cols()

    stmt = (
        select(UserActivityEvent, full_name_col, email_col, User.role)
        .outerjoin(User, User.id == UserActivityEvent.user_id)
    )
    stmt = _apply_time_filters(stmt, UserActivityEvent.occurred_at)

    if ctx["action"]:
        stmt = stmt.where(UserActivityEvent.action == ctx["action"])
    if ctx["target_type"]:
        stmt = stmt.where(UserActivityEvent.target_type == ctx["target_type"])
    if ctx["actor_id"]:
        stmt = stmt.where(UserActivityEvent.user_id == ctx["actor_id"])
    if ctx["role"]:
        stmt = stmt.where(UserActivityEvent.role_name == ctx["role"])
    if ctx["status"]:
        stmt = stmt.where(UserActivityEvent.status == ctx["status"])

    if ctx["q"]:
        like = f"%{ctx['q']}%"
        stmt = stmt.where(
            or_(
                UserActivityEvent.action.ilike(like),
                UserActivityEvent.target_type.ilike(like),
                UserActivityEvent.route.ilike(like),
                full_name_col.ilike(like),
                email_col.ilike(like),
            )
        )

    return stmt


def _build_auth_query() -> Select[Any]:
    ctx = _filter_context()
    full_name_col, email_col = _user_display_cols()

    stmt = (
        select(LoginEvent, full_name_col, email_col, User.role)
        .outerjoin(User, User.id == LoginEvent.user_id)
    )
    stmt = _apply_time_filters(stmt, LoginEvent.created_at)

    if ctx["action"]:
        stmt = stmt.where(LoginEvent.event_type == ctx["action"])
    else:
        stmt = stmt.where(LoginEvent.event_type.notin_(tuple(NOISY_AUTH_EVENT_TYPES)))

    if ctx["actor_id"]:
        stmt = stmt.where(LoginEvent.user_id == ctx["actor_id"])

    if ctx["role"]:
        role_int = ROLE_NAME_TO_INT.get(ctx["role"])
        if role_int is not None:
            stmt = stmt.where(User.role == role_int)

    if ctx["q"]:
        like = f"%{ctx['q']}%"
        stmt = stmt.where(
            or_(
                LoginEvent.event_type.ilike(like),
                full_name_col.ilike(like),
                email_col.ilike(like),
                LoginEvent.ip_address.ilike(like),
                LoginEvent.user_agent.ilike(like),
            )
        )

    return stmt


# ----------------------------------------------------------------------------
# SQL fallback queries
# ----------------------------------------------------------------------------
def _date_sql(column: str) -> tuple[list[str], dict[str, Any]]:
    clauses: list[str] = []
    params: dict[str, Any] = {}

    from_dt, to_dt, _days = _date_range_from_request()

    if from_dt is not None:
        clauses.append(f"{column} >= :from_dt")
        params["from_dt"] = from_dt
    if to_dt is not None:
        clauses.append(f"{column} <= :to_dt")
        params["to_dt"] = to_dt

    return clauses, params


def _fallback_governance_rows(max_rows: int) -> list[dict[str, Any]]:
    if not _table_exists("product_moderation_events"):
        return []

    ctx = _filter_context()
    clauses, params = _date_sql("pm.created_at")
    clauses.append("lower(coalesce(pm.actor_role, '')) = 'admin'")

    if ctx["action"]:
        clauses.append("lower(coalesce(pm.action, '')) = :action")
        params["action"] = ctx["action"].lower()

    if ctx["actor_id"]:
        clauses.append("pm.actor_id = :actor_id")
        params["actor_id"] = str(ctx["actor_id"])

    if ctx["q"]:
        clauses.append(
            "("
            "lower(coalesce(pm.action, '')) LIKE :like "
            "OR lower(coalesce(pm.notes, '')) LIKE :like "
            "OR lower(coalesce(u.full_name, '')) LIKE :like "
            "OR lower(coalesce(u.email, '')) LIKE :like "
            ")"
        )
        params["like"] = f"%{ctx['q'].lower()}%"

    where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""
    params["max_rows"] = max_rows

    sql = text(
        f"""
        SELECT
            pm.id::text AS id,
            pm.created_at AS occurred_at,
            pm.actor_id AS actor_id,
            u.full_name AS actor_name,
            u.email AS actor_email,
            'admin' AS actor_role,
            pm.action AS action,
            'product' AS target_type,
            pm.product_id AS target_id,
            'success' AS status,
            NULL::text AS route,
            NULL::text AS http_method,
            NULL::text AS ip_address,
            NULL::text AS user_agent,
            jsonb_build_object(
                'notes', pm.notes,
                'changed_fields', pm.changed_fields_json,
                'before', pm.before_json,
                'after', pm.after_json
            ) AS metadata,
            'product_moderation_events' AS source_table
        FROM product_moderation_events pm
        LEFT JOIN users u
          ON u.id = (
            CASE
              WHEN pm.actor_id ~* '^[0-9a-fA-F-]{{36}}$' THEN pm.actor_id::uuid
              ELSE NULL
            END
          )
        {where_sql}
        ORDER BY pm.created_at DESC
        LIMIT :max_rows
        """
    )

    try:
        rows = db.session.execute(sql, params).mappings().all()
        return [dict(row) for row in rows]
    except Exception:
        return []


def _fallback_activity_rows(max_rows: int) -> list[dict[str, Any]]:
    ctx = _filter_context()
    role_int = ROLE_NAME_TO_INT.get(ctx["role"] or "")
    out: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # product_engagement_events
    # ------------------------------------------------------------------
    if _table_exists("product_engagement_events"):
        clauses, params = _date_sql("pe.created_at")

        if ctx["action"] and ctx["action"].lower() != "search":
            clauses.append("lower(coalesce(pe.event_type, '')) = :action")
            params["action"] = ctx["action"].lower()

        if ctx["actor_id"]:
            clauses.append("pe.user_id = :actor_id")
            params["actor_id"] = str(ctx["actor_id"])

        if role_int is not None:
            clauses.append("u.role = :role_int")
            params["role_int"] = role_int

        if ctx["q"]:
            clauses.append(
                "("
                "lower(coalesce(pe.event_type, '')) LIKE :like "
                "OR lower(coalesce(u.full_name, '')) LIKE :like "
                "OR lower(coalesce(u.email, '')) LIKE :like "
                "OR lower(coalesce(p.product_name, '')) LIKE :like "
                ")"
            )
            params["like"] = f"%{ctx['q'].lower()}%"

        params["max_rows"] = max_rows
        where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""

        sql = text(
            f"""
            SELECT
                pe.id::text AS id,
                pe.created_at AS occurred_at,
                pe.user_id::text AS actor_id,
                u.full_name AS actor_name,
                u.email AS actor_email,
                CASE u.role WHEN 1 THEN 'admin' WHEN 2 THEN 'farmer' WHEN 3 THEN 'customer' ELSE 'unknown' END AS actor_role,
                lower(coalesce(pe.event_type, 'engagement')) AS action,
                'product' AS target_type,
                pe.product_id::text AS target_id,
                'success' AS status,
                NULL::text AS route,
                NULL::text AS http_method,
                NULL::text AS ip_address,
                NULL::text AS user_agent,
                jsonb_build_object('product_name', p.product_name) AS metadata,
                'product_engagement_events' AS source_table
            FROM product_engagement_events pe
            LEFT JOIN users u ON u.id = pe.user_id
            LEFT JOIN products p ON p.product_id = pe.product_id
            {where_sql}
            ORDER BY pe.created_at DESC
            LIMIT :max_rows
            """
        )

        try:
            out.extend(dict(row) for row in db.session.execute(sql, params).mappings().all())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # customer_search_events
    # ------------------------------------------------------------------
    if _table_exists("customer_search_events") and (not ctx["action"] or ctx["action"].lower() == "search"):
        clauses, params = _date_sql("cs.created_at")

        if ctx["actor_id"]:
            clauses.append("cs.user_id = :actor_id")
            params["actor_id"] = str(ctx["actor_id"])

        if role_int is not None:
            clauses.append("u.role = :role_int")
            params["role_int"] = role_int

        if ctx["q"]:
            clauses.append(
                "("
                "lower(coalesce(cs.query, '')) LIKE :like "
                "OR lower(coalesce(u.full_name, '')) LIKE :like "
                "OR lower(coalesce(u.email, '')) LIKE :like "
                ")"
            )
            params["like"] = f"%{ctx['q'].lower()}%"

        params["max_rows"] = max_rows
        where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""

        sql = text(
            f"""
            SELECT
                cs.id::text AS id,
                cs.created_at AS occurred_at,
                cs.user_id::text AS actor_id,
                u.full_name AS actor_name,
                u.email AS actor_email,
                CASE u.role WHEN 1 THEN 'admin' WHEN 2 THEN 'farmer' WHEN 3 THEN 'customer' ELSE 'unknown' END AS actor_role,
                'search' AS action,
                'search' AS target_type,
                NULL::text AS target_id,
                'success' AS status,
                '/api/events/search' AS route,
                'POST' AS http_method,
                NULL::text AS ip_address,
                NULL::text AS user_agent,
                jsonb_build_object('query', cs.query) AS metadata,
                'customer_search_events' AS source_table
            FROM customer_search_events cs
            LEFT JOIN users u ON u.id = cs.user_id
            {where_sql}
            ORDER BY cs.created_at DESC
            LIMIT :max_rows
            """
        )

        try:
            out.extend(dict(row) for row in db.session.execute(sql, params).mappings().all())
        except Exception:
            pass

    # ------------------------------------------------------------------
    # notifications
    # ------------------------------------------------------------------
    if _table_exists("notifications"):
        clauses, params = _date_sql("n.created_at")
        clauses.append("n.actor_user_id IS NOT NULL")

        if ctx["action"]:
            clauses.append("lower(coalesce(n.notification_type, '')) = :action")
            params["action"] = ctx["action"].lower()

        if ctx["actor_id"]:
            clauses.append("n.actor_user_id = :actor_id")
            params["actor_id"] = str(ctx["actor_id"])

        if role_int is not None:
            clauses.append("u.role = :role_int")
            params["role_int"] = role_int

        if ctx["q"]:
            clauses.append(
                "("
                "lower(coalesce(n.notification_type, '')) LIKE :like "
                "OR lower(coalesce(n.title, '')) LIKE :like "
                "OR lower(coalesce(n.message, '')) LIKE :like "
                "OR lower(coalesce(u.full_name, '')) LIKE :like "
                "OR lower(coalesce(u.email, '')) LIKE :like "
                ")"
            )
            params["like"] = f"%{ctx['q'].lower()}%"

        params["max_rows"] = max_rows
        where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""

        sql = text(
            f"""
            SELECT
                n.notification_id::text AS id,
                n.created_at AS occurred_at,
                n.actor_user_id::text AS actor_id,
                u.full_name AS actor_name,
                u.email AS actor_email,
                CASE u.role WHEN 1 THEN 'admin' WHEN 2 THEN 'farmer' WHEN 3 THEN 'customer' ELSE 'unknown' END AS actor_role,
                lower(coalesce(n.notification_type, 'notification')) AS action,
                CASE WHEN n.order_id IS NOT NULL THEN 'order' ELSE 'notification' END AS target_type,
                COALESCE(n.order_id::text, n.notification_id::text) AS target_id,
                'success' AS status,
                NULL::text AS route,
                NULL::text AS http_method,
                NULL::text AS ip_address,
                NULL::text AS user_agent,
                COALESCE(n.data_json, '{{}}'::jsonb) AS metadata,
                'notifications' AS source_table
            FROM notifications n
            LEFT JOIN users u ON u.id = n.actor_user_id
            {where_sql}
            ORDER BY n.created_at DESC
            LIMIT :max_rows
            """
        )

        try:
            out.extend(dict(row) for row in db.session.execute(sql, params).mappings().all())
        except Exception:
            pass

    # Use stringified sort key to avoid mixed datetime / string comparison issues.
    out.sort(key=lambda item: str(item.get("occurred_at") or ""), reverse=True)
    return out[:max_rows]


# ----------------------------------------------------------------------------
# Counts / health / insights
# ----------------------------------------------------------------------------
def _count_governance() -> int:
    total = 0

    if _table_exists("admin_audit_log"):
        try:
            stmt = select(func.count()).select_from(AdminAuditLog)
            stmt = _apply_time_filters(stmt, AdminAuditLog.created_at)
            total += int(db.session.execute(stmt).scalar() or 0)
        except Exception:
            pass

    if _table_exists("product_moderation_events"):
        clauses, params = _date_sql("pm.created_at")
        clauses.append("lower(coalesce(pm.actor_role, '')) = 'admin'")
        where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = text(f"SELECT COUNT(*) AS c FROM product_moderation_events pm {where_sql}")

        try:
            total += int(db.session.execute(sql, params).scalar() or 0)
        except Exception:
            pass

    return total


def _count_activity() -> int:
    total = 0

    if _table_exists("user_activity_events"):
        try:
            stmt = select(func.count()).select_from(UserActivityEvent)
            stmt = _apply_time_filters(stmt, UserActivityEvent.occurred_at)
            total += int(db.session.execute(stmt).scalar() or 0)
        except Exception:
            pass

    for table_name, col_name in [
        ("product_engagement_events", "created_at"),
        ("customer_search_events", "created_at"),
        ("notifications", "created_at"),
    ]:
        if not _table_exists(table_name):
            continue

        clauses, params = _date_sql(f"t.{col_name}")
        if table_name == "notifications":
            clauses.append("t.actor_user_id IS NOT NULL")

        where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = text(f"SELECT COUNT(*) AS c FROM {table_name} t {where_sql}")

        try:
            total += int(db.session.execute(sql, params).scalar() or 0)
        except Exception:
            pass

    return total


def _count_auth_events(event_type: Optional[str] = None, *, include_seen: bool = False) -> int:
    if not _table_exists("login_events"):
        return 0

    try:
        stmt = select(func.count()).select_from(LoginEvent)
        stmt = _apply_time_filters(stmt, LoginEvent.created_at)

        if event_type:
            stmt = stmt.where(LoginEvent.event_type == event_type)
        elif not include_seen:
            stmt = stmt.where(LoginEvent.event_type.notin_(tuple(NOISY_AUTH_EVENT_TYPES)))

        return int(db.session.execute(stmt).scalar() or 0)
    except Exception:
        return 0


def _count_active_users_recent(window_minutes: int = 10) -> int:
    """
    Prefer ORM when the mapped attribute exists.
    Fall back to raw SQL when the DB column exists but the ORM model has not
    declared User.last_seen_at yet.
    """
    cutoff = datetime.utcnow() - timedelta(minutes=max(1, min(window_minutes, 240)))

    deleted_at_col: Any = _user_attr("deleted_at")
    is_active_col: Any = _user_attr("is_active")
    last_seen_col: Any = _user_attr("last_seen_at")

    # ------------------------------------------------------------------
    # ORM path — only when the model actually exposes the needed columns.
    # ------------------------------------------------------------------
    if deleted_at_col is not None and is_active_col is not None and last_seen_col is not None:
        try:
            stmt = (
                select(func.count())
                .select_from(User)
                .where(
                    and_(
                        deleted_at_col.is_(None),
                        is_active_col.is_(True),
                        last_seen_col.is_not(None),
                        last_seen_col >= cutoff,
                    )
                )
            )
            count = int(db.session.execute(stmt).scalar() or 0)
            if count > 0:
                return count
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SQL path — safe when schema has the column even if ORM model lags behind.
    # ------------------------------------------------------------------
    if _table_exists("users"):
        try:
            sql = text(
                """
                SELECT COUNT(*) AS c
                FROM users u
                WHERE u.deleted_at IS NULL
                  AND COALESCE(u.is_active, TRUE) = TRUE
                  AND u.last_seen_at IS NOT NULL
                  AND u.last_seen_at >= :cutoff
                """
            )
            count = int(db.session.execute(sql, {"cutoff": cutoff}).scalar() or 0)
            if count > 0:
                return count
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Final fallback — derive "online now" from recent auth heartbeat/session rows.
    # ------------------------------------------------------------------
    if not _table_exists("login_events"):
        return 0

    try:
        sql = text(
            """
            SELECT COUNT(DISTINCT le.user_id) AS c
            FROM login_events le
            WHERE le.created_at >= :cutoff
              AND lower(coalesce(le.event_type, '')) IN ('seen', 'login', 'refresh')
            """
        )
        return int(db.session.execute(sql, {"cutoff": cutoff}).scalar() or 0)
    except Exception:
        return 0


def _table_health() -> dict[str, dict[str, Any]]:
    auth_primary = _table_exists("login_events")
    activity_primary = _table_exists("user_activity_events")
    governance_primary = _table_exists("admin_audit_log")
    governance_fallback = _table_exists("product_moderation_events")

    return {
        "auth": {
            "available": auth_primary,
            "primary": "login_events",
            "rows": _count_auth_events(None),
            "heartbeat_rows": _count_auth_events("seen", include_seen=True),
            "note": (
                "Auth evidence is live from login_events. Heartbeat 'seen' rows are excluded from KPIs to keep the dashboard readable."
                if auth_primary
                else "login_events is unavailable, so auth auditing cannot be shown."
            ),
        },
        "activity": {
            "available": (
                activity_primary
                or _table_exists("product_engagement_events")
                or _table_exists("customer_search_events")
                or _table_exists("notifications")
            ),
            "primary": "user_activity_events",
            "rows": _count_activity(),
            "note": (
                "Primary activity audit is active in user_activity_events."
                if activity_primary
                else "Primary activity audit table is missing; fallback evidence is being reconstructed from product engagement, search, and notification traces."
            ),
        },
        "governance": {
            "available": governance_primary or governance_fallback,
            "primary": "admin_audit_log",
            "rows": _count_governance(),
            "note": (
                "Governance audit is active in admin_audit_log."
                if governance_primary and _count_governance() > 0
                else (
                    "admin_audit_log is empty; governance history is being reconstructed from product_moderation_events."
                    if governance_fallback
                    else "No governance evidence source is currently available."
                )
            ),
        },
    }


def _auth_timeline() -> dict[str, Any]:
    labels: list[str] = []
    login_series: list[int] = []
    logout_series: list[int] = []
    failed_series: list[int] = []

    from_dt, to_dt, days = _date_range_from_request()
    if from_dt is None or to_dt is None:
        span = max(7, min(days or 30, 365))
        to_dt = datetime.utcnow()
        from_dt = to_dt - timedelta(days=span)

    day_cursor = from_dt.date()
    end_day = to_dt.date()
    dense_days: list[Any] = []

    while day_cursor <= end_day:
        dense_days.append(day_cursor)
        day_cursor += timedelta(days=1)

    rows_by_key: dict[tuple[str, str], int] = {}

    if _table_exists("login_events"):
        sql = text(
            """
            SELECT
                DATE(le.created_at) AS day,
                lower(coalesce(le.event_type, '')) AS event_type,
                COUNT(*) AS c
            FROM login_events le
            WHERE le.created_at >= :from_dt
              AND le.created_at <= :to_dt
              AND lower(coalesce(le.event_type, '')) IN ('login', 'logout', 'logout_all', 'failed_login')
            GROUP BY DATE(le.created_at), lower(coalesce(le.event_type, ''))
            ORDER BY DATE(le.created_at) ASC
            """
        )

        try:
            for row in db.session.execute(sql, {"from_dt": from_dt, "to_dt": to_dt}).mappings().all():
                day_value = row.get("day")
                event_type = _safe_str(row.get("event_type")) or "unknown"
                if day_value is not None:
                    rows_by_key[(str(day_value), event_type)] = int(row.get("c") or 0)
        except Exception:
            pass

    for day_value in dense_days:
        day_key = str(day_value)
        labels.append(day_key)
        login_series.append(rows_by_key.get((day_key, "login"), 0))
        logout_series.append(
            rows_by_key.get((day_key, "logout"), 0)
            + rows_by_key.get((day_key, "logout_all"), 0)
        )
        failed_series.append(rows_by_key.get((day_key, "failed_login"), 0))

    return {
        "labels": labels,
        "login": login_series,
        "logout": logout_series,
        "failed_login": failed_series,
    }


def _collect_combined(max_rows: int) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    health = _table_health()
    combined: list[dict[str, Any]] = []
    stream = _normalize_stream(request.args.get("stream"))

    # Governance primary
    if stream in {"all", "governance"} and _table_exists("admin_audit_log"):
        try:
            rows = db.session.execute(
                _build_governance_query()
                .order_by(AdminAuditLog.created_at.desc())
                .limit(max_rows)
            ).all()
            combined.extend(_governance_row_to_dict(row) for row in rows)
        except Exception:
            pass

    # Governance fallback
    if stream in {"all", "governance"}:
        combined.extend(_fallback_governance_rows(max_rows))

    # Activity primary
    if stream in {"all", "activity"} and _table_exists("user_activity_events"):
        try:
            rows = db.session.execute(
                _build_activity_query()
                .order_by(UserActivityEvent.occurred_at.desc())
                .limit(max_rows)
            ).all()
            combined.extend(_activity_row_to_dict(row) for row in rows)
        except Exception:
            pass

    # Activity fallback
    if stream in {"all", "activity"}:
        combined.extend(_fallback_activity_rows(max_rows))

    # Auth
    if stream in {"all", "auth"} and _table_exists("login_events"):
        try:
            rows = db.session.execute(
                _build_auth_query()
                .order_by(LoginEvent.created_at.desc())
                .limit(max_rows)
            ).all()
            combined.extend(_auth_row_to_dict(row) for row in rows)
        except Exception:
            pass

    combined.sort(key=lambda item: str(item.get("occurred_at") or ""), reverse=True)
    return combined, health


def _derive_insights(summary_payload: dict[str, Any], rows: list[dict[str, Any]]) -> list[dict[str, str]]:
    auth = summary_payload.get("auth") or {}
    health = summary_payload.get("health") or {}
    streams = summary_payload.get("streams") or {}

    insights: list[dict[str, str]] = []

    if health.get("activity", {}).get("primary") == "user_activity_events" and not _table_exists("user_activity_events"):
        insights.append(
            {
                "level": "warning",
                "title": "Primary activity audit is not installed",
                "description": "The dashboard is reconstructing activity from fallback evidence. Apply the audit SQL patch so user_activity_events starts capturing first-class behavior traces.",
            }
        )

    login_count = int(auth.get("logins") or 0)
    if login_count > 0:
        insights.append(
            {
                "level": "success",
                "title": "Authentication evidence is live",
                "description": f"There were {login_count} logins in the selected window, so the auth stream is working and can support real usage analysis.",
            }
        )

    failed = int(auth.get("failed_logins") or 0)
    if failed > 0:
        rate = (failed / max(1, login_count + failed)) * 100.0
        insights.append(
            {
                "level": "warning" if rate >= 10 else "info",
                "title": "Failed login rate detected",
                "description": f"Failed logins account for {rate:.1f}% of observed auth attempts in this window. Review whether this reflects normal error, credential reuse, or brute-force behavior.",
            }
        )

    if int(streams.get("governance") or 0) == 0:
        insights.append(
            {
                "level": "info",
                "title": "No governance actions in the selected period",
                "description": "Either no privileged decisions were made in this window, or governance evidence has not been backfilled yet. Expanding the date range usually helps validate which is true.",
            }
        )

    action_counter = Counter(str(row.get("action") or "unknown") for row in rows)
    if action_counter:
        dominant_action, dominant_count = action_counter.most_common(1)[0]
        insights.append(
            {
                "level": "info",
                "title": "Dominant action in current evidence",
                "description": f"The most frequent action in the current view is '{dominant_action}' with {dominant_count} occurrences, which is a strong starting point for operational interpretation.",
            }
        )

    return insights[:4]


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@admin_audit_bp.route("/audit-log", methods=["GET"])
@require_access_token
def audit_log() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    limit, offset = _limit_and_offset()
    combined, health = _collect_combined(limit + offset + 200)
    paged = combined[offset : offset + limit]

    return _json(
        {
            "success": True,
            "items": paged,
            "logs": paged,
            "count": len(paged),
            "total_estimate": len(combined),
            "stream": _normalize_stream(request.args.get("stream")),
            "limit": limit,
            "offset": offset,
            "health": health,
        },
        200,
    )


@admin_audit_bp.route("/audit-log/summary", methods=["GET"])
@require_access_token
def audit_log_summary() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    combined, health = _collect_combined(1000)

    logins = _count_auth_events("login")
    logouts = _count_auth_events("logout")
    logout_all = _count_auth_events("logout_all")
    refreshes = _count_auth_events("refresh")
    failed_logins = _count_auth_events("failed_login")
    session_expired = _count_auth_events("session_expired")
    token_revoked = _count_auth_events("token_revoked")

    stream_counter = Counter(str(row.get("stream") or "unknown") for row in combined)
    action_counter = Counter(str(row.get("action") or "unknown") for row in combined)

    actor_counter: defaultdict[tuple[str, str, str], int] = defaultdict(int)
    for row in combined:
        key = (
            _safe_str(row.get("actor_name")) or "Unknown user",
            _safe_str(row.get("actor_email")) or "",
            _safe_str(row.get("actor_role")) or "unknown",
        )
        actor_counter[key] += 1

    top_actions = [
        {"action": action, "count": count}
        for action, count in action_counter.most_common(8)
    ]

    top_actors = [
        {
            "actor_name": actor_name,
            "actor_email": actor_email,
            "actor_role": actor_role,
            "count": count,
        }
        for (actor_name, actor_email, actor_role), count in sorted(
            actor_counter.items(),
            key=lambda item: item[1],
            reverse=True,
        )[:8]
    ]

    payload = {
        "auth": {
            "logins": logins,
            "logouts": logouts,
            "logout_all": logout_all,
            "refreshes": refreshes,
            "failed_logins": failed_logins,
            "session_expired": session_expired,
            "token_revoked": token_revoked,
            "active_users_now": _count_active_users_recent(10),
        },
        "streams": {
            "governance": int(stream_counter.get("governance", 0)),
            "activity": int(stream_counter.get("activity", 0)),
            "auth": int(stream_counter.get("auth", 0)),
        },
        "filters": {
            "from": _safe_str(request.args.get("from") or request.args.get("start")),
            "to": _safe_str(request.args.get("to") or request.args.get("end")),
            "days": _to_int(request.args.get("days"), 0),
        },
        "health": health,
        "timeline": _auth_timeline(),
        "top_actions": top_actions,
        "top_actors": top_actors,
    }
    payload["insights"] = _derive_insights(payload, combined)

    return _json({"success": True, "summary": payload}, 200)