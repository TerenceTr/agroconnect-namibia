# ============================================================================
# backend/services/admin_reports/report_exporter.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Central report builder + exporter for admin standard and ad hoc reports.
#
# SUPPORTED REPORT KEYS:
#   - auth_activity
#   - user_activity
#   - product_lifecycle
#   - product_search_statistics
#   - moderation_sla
#
# EXPORT FORMATS:
#   - csv
#   - pdf
#
# KEY IMPROVEMENTS IN THIS VERSION:
#   ✅ Stops silently swallowing SQL errors that previously looked like "0 rows"
#   ✅ Uses schema-aware user name SQL so missing columns like name/username
#      do not break the query on this database
#   ✅ Adds fallback activity sourcing from admin_audit_log when needed
#   ✅ Keeps the professional ReportLab PDF unless ReportLab is actually missing
#   ✅ Stabilizes wide tables in PDF output with deterministic column widths
#   ✅ Produces more trustworthy previews and exports for the admin dashboard
# ============================================================================
from __future__ import annotations

import csv
import io
import logging
from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# Standard report window expansion
# ----------------------------------------------------------------------------
AUTO_EXPAND_STANDARD_DAYS: Dict[str, int] = {
    "product_lifecycle": 90,
    "product_search_statistics": 90,
    "moderation_sla": 90,
}

# ----------------------------------------------------------------------------
# Lightweight metadata cache to avoid repeated information_schema calls
# ----------------------------------------------------------------------------
_TABLE_COLUMNS_CACHE: Dict[str, Set[str]] = {}


# ----------------------------------------------------------------------------
# Types
# ----------------------------------------------------------------------------
@dataclass
class ReportContext:
    report_key: str
    title: str
    subtitle: str
    generated_at: datetime
    generated_by_name: str
    generated_by_email: Optional[str]
    export_format: str
    period: str
    date_from: Optional[datetime]
    date_to: Optional[datetime]
    filters: Dict[str, Any]


@dataclass
class BuiltReport:
    context: ReportContext
    columns: List[str]
    rows: List[Dict[str, Any]]
    summary: Dict[str, Any]
    filename_base: str


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        text_value = str(value).strip()
    except Exception:
        return default
    return text_value or default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _parse_dt(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value

    raw = _safe_str(value)
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


def _iso(value: Any) -> Optional[str]:
    try:
        return value.isoformat() if value else None
    except Exception:
        return None


def _normalize_period(value: Any) -> str:
    raw = _safe_str(value, "month").lower()
    if raw in {"day", "daily"}:
        return "day"
    if raw in {"week", "weekly"}:
        return "week"
    if raw in {"month", "monthly"}:
        return "month"
    if raw in {"year", "annual", "annually", "yearly"}:
        return "year"
    return "month"


def _date_window_from_filters(filters: Dict[str, Any]) -> Tuple[Optional[datetime], Optional[datetime]]:
    """
    Resolve the effective report window.
    Priority:
      1) explicit date_from/date_to
      2) explicit days override
      3) period + span
    """
    date_from = _parse_dt(filters.get("date_from") or filters.get("from"))
    date_to = _parse_dt(filters.get("date_to") or filters.get("to"))

    if date_from or date_to:
        return date_from, date_to

    days = _safe_int(filters.get("days"), 0)
    if days > 0:
        end_dt = datetime.utcnow()
        start_dt = end_dt - timedelta(days=max(1, min(days, 3650)))
        return start_dt, end_dt

    period = _normalize_period(filters.get("period"))
    span = max(1, min(_safe_int(filters.get("span"), 12), 120))
    end_dt = datetime.utcnow()

    if period == "day":
        start_dt = end_dt - timedelta(days=span)
    elif period == "week":
        start_dt = end_dt - timedelta(days=span * 7)
    elif period == "year":
        start_dt = end_dt - timedelta(days=span * 365)
    else:
        start_dt = end_dt - timedelta(days=span * 30)

    return start_dt, end_dt


def _build_filename_base(report_key: str, generated_at: datetime) -> str:
    stamp = generated_at.strftime("%Y-%m-%d_%H-%M")
    return f"agroconnect_{report_key}_{stamp}"


def _filters_line(filters: Dict[str, Any]) -> str:
    chunks: List[str] = []
    for key, value in filters.items():
        if value in (None, "", [], {}):
            continue
        chunks.append(f"{key}={value}")
    return " • ".join(chunks)


def _csv_bytes(columns: Sequence[str], rows: Sequence[Dict[str, Any]], report: Optional[BuiltReport] = None) -> bytes:
    """
    Produce CSV with report metadata on top for a more professional export.
    """
    buf = io.StringIO()
    writer = csv.writer(buf)

    if report is not None:
        ctx = report.context
        writer.writerow(["Report title", ctx.title])
        writer.writerow(["Subtitle", ctx.subtitle])
        writer.writerow(["Generated by", ctx.generated_by_name])
        writer.writerow(["Generated by email", ctx.generated_by_email or ""])
        writer.writerow(["Generated at UTC", ctx.generated_at.strftime("%Y-%m-%d %H:%M:%S")])
        writer.writerow(["Period", ctx.period])
        writer.writerow(["Date from", ctx.date_from.strftime("%Y-%m-%d %H:%M:%S") if ctx.date_from else ""])
        writer.writerow(["Date to", ctx.date_to.strftime("%Y-%m-%d %H:%M:%S") if ctx.date_to else ""])
        if ctx.filters:
            writer.writerow(["Applied filters", _filters_line(ctx.filters)])

        for key, value in (report.summary or {}).items():
            writer.writerow([f"Summary: {key}", value])

        writer.writerow([])

    writer.writerow(list(columns))
    for row in rows:
        writer.writerow([row.get(col) for col in columns])

    return ("﻿" + buf.getvalue()).encode("utf-8")


def _top_n(counter_like: Dict[str, float], n: int = 6) -> List[Tuple[str, float]]:
    items = [(k, v) for k, v in counter_like.items() if k]
    items.sort(key=lambda item: item[1], reverse=True)
    return items[:n]


def _compact_label(label: str, limit: int = 16) -> str:
    value = _safe_str(label)
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _bucket_from_iso(ts: Optional[str], period: str) -> Optional[str]:
    if not ts:
        return None
    dt = _parse_dt(ts)
    if not dt:
        return None

    if period == "year":
        return dt.strftime("%Y")
    if period == "week":
        year, week, _ = dt.isocalendar()
        return f"{year}-W{week:02d}"
    if period == "day":
        return dt.strftime("%Y-%m-%d")
    return dt.strftime("%Y-%m")


def _safe_mappings(
    session: Session,
    sql: str,
    params: Dict[str, Any],
    *,
    swallow_errors: bool = False,
) -> List[Dict[str, Any]]:
    """
    Execute a SQL text query and return rows as normal dicts.

    IMPORTANT:
    - We do NOT want broken SQL to quietly look like a valid empty report.
    - swallow_errors=True is only for optional metadata lookups/fallback checks.
    """
    try:
        rows = session.execute(text(sql), params).mappings().all()
        return [dict(row) for row in rows]
    except Exception:
        logger.exception("Admin report SQL failed", extra={"sql": sql, "params": params})
        if swallow_errors:
            return []
        raise


# ----------------------------------------------------------------------------
# Schema awareness helpers
# ----------------------------------------------------------------------------
def _table_exists(session: Session, table_name: str) -> bool:
    sql = """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_name = :table_name
        ) AS exists_flag
    """
    rows = _safe_mappings(session, sql, {"table_name": table_name}, swallow_errors=True)
    return bool(rows and rows[0].get("exists_flag"))


def _table_columns(session: Session, table_name: str) -> Set[str]:
    """
    Read and cache table columns from information_schema.
    """
    cache_key = f"public.{table_name}"
    if cache_key in _TABLE_COLUMNS_CACHE:
        return _TABLE_COLUMNS_CACHE[cache_key]

    sql = """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = :table_name
    """
    rows = _safe_mappings(session, sql, {"table_name": table_name}, swallow_errors=True)
    columns = {str(row.get("column_name")) for row in rows if row.get("column_name")}
    _TABLE_COLUMNS_CACHE[cache_key] = columns
    return columns


def _column_exists(session: Session, table_name: str, column_name: str) -> bool:
    return column_name in _table_columns(session, table_name)


def _coalesce_user_name_sql(session: Session, alias: str = "u") -> str:
    """
    Build a safe SQL expression for user display name based on columns that
    actually exist in the current users table.

    This avoids SQL errors on databases that have full_name/email but do not
    have name/username columns.
    """
    cols = _table_columns(session, "users")
    candidates: List[str] = []

    for col in ("full_name", "name", "username", "email"):
        if col in cols:
            candidates.append(f"NULLIF(TRIM(COALESCE({alias}.{col}::text, '')), '')")

    if not candidates:
        return "'Unknown'"

    return "COALESCE(" + ", ".join(candidates) + ", 'Unknown')"


# ----------------------------------------------------------------------------
# Query builders
# ----------------------------------------------------------------------------
def _build_auth_activity_report(session: Session, context: ReportContext) -> BuiltReport:
    columns = [
        "occurred_at",
        "user_name",
        "user_email",
        "role",
        "event_type",
        "ip_address",
        "user_agent",
    ]
    rows: List[Dict[str, Any]] = []

    if not _table_exists(session, "login_events"):
        raise ValueError("login_events table does not exist. Authentication report cannot be generated.")

    user_name_sql = _coalesce_user_name_sql(session, "u")

    where_parts = ["1=1"]
    params: Dict[str, Any] = {
        "limit": max(1, min(_safe_int(context.filters.get("limit"), 500), 5000))
    }

    if context.date_from is not None:
        where_parts.append("le.created_at >= :date_from")
        params["date_from"] = context.date_from

    if context.date_to is not None:
        where_parts.append("le.created_at <= :date_to")
        params["date_to"] = context.date_to

    event_type_filter = _safe_str(context.filters.get("event_type") or context.filters.get("action")).lower()
    if event_type_filter:
        where_parts.append("LOWER(COALESCE(le.event_type, '')) = :event_type")
        params["event_type"] = event_type_filter

    role_filter = _safe_str(context.filters.get("role")).lower()
    role_map = {"admin": 1, "farmer": 2, "customer": 3}
    role_int = role_map.get(role_filter)
    if role_int is not None:
        where_parts.append("u.role = :role_int")
        params["role_int"] = role_int

    q = _safe_str(context.filters.get("q"))
    if q:
        where_parts.append(
            "("
            "COALESCE(le.event_type, '') ILIKE :q OR "
            "COALESCE(le.ip_address, '') ILIKE :q OR "
            "COALESCE(le.user_agent, '') ILIKE :q OR "
            f"{user_name_sql} ILIKE :q OR "
            "COALESCE(u.email, '') ILIKE :q"
            ")"
        )
        params["q"] = f"%{q}%"

    sql = f"""
        SELECT
            le.created_at AS occurred_at,
            {user_name_sql} AS user_name,
            COALESCE(u.email, '') AS user_email,
            CASE COALESCE(CAST(u.role AS TEXT), '0')
                WHEN '1' THEN 'admin'
                WHEN '2' THEN 'farmer'
                WHEN '3' THEN 'customer'
                ELSE 'unknown'
            END AS role,
            LOWER(COALESCE(le.event_type, '')) AS event_type,
            COALESCE(le.ip_address, '') AS ip_address,
            COALESCE(le.user_agent, '') AS user_agent
        FROM public.login_events le
        LEFT JOIN public.users u ON u.id = le.user_id
        WHERE {" AND ".join(where_parts)}
        ORDER BY le.created_at DESC
        LIMIT :limit
    """

    for row in _safe_mappings(session, sql, params):
        rows.append(
            {
                "occurred_at": _iso(row.get("occurred_at")),
                "user_name": _safe_str(row.get("user_name"), "Unknown"),
                "user_email": _safe_str(row.get("user_email")),
                "role": _safe_str(row.get("role"), "unknown"),
                "event_type": _safe_str(row.get("event_type")),
                "ip_address": _safe_str(row.get("ip_address")),
                "user_agent": _safe_str(row.get("user_agent")),
            }
        )

    summary = {
        "total_events": len(rows),
        "login_count": sum(1 for row in rows if row["event_type"] == "login"),
        "logout_count": sum(1 for row in rows if row["event_type"] == "logout"),
        "failed_login_count": sum(1 for row in rows if row["event_type"] == "failed_login"),
        "refresh_count": sum(1 for row in rows if row["event_type"] == "refresh"),
        "unique_users": len({row["user_email"] for row in rows if row["user_email"]}),
    }

    return BuiltReport(
        context=context,
        columns=columns,
        rows=rows,
        summary=summary,
        filename_base=_build_filename_base(context.report_key, context.generated_at),
    )


def _build_user_activity_report(session: Session, context: ReportContext) -> BuiltReport:
    columns = [
        "occurred_at",
        "user_name",
        "user_email",
        "role",
        "action",
        "target_type",
        "target_id",
        "status",
        "route",
        "ip_address",
    ]
    rows: List[Dict[str, Any]] = []

    user_name_sql = _coalesce_user_name_sql(session, "u")
    limit = max(1, min(_safe_int(context.filters.get("limit"), 500), 5000))

    # ---------------------------------------------------------------------
    # Primary source: user_activity_events
    # ---------------------------------------------------------------------
    if _table_exists(session, "user_activity_events"):
        where_parts = ["1=1"]
        params: Dict[str, Any] = {"limit": limit}

        if context.date_from is not None:
            where_parts.append("uae.occurred_at >= :date_from")
            params["date_from"] = context.date_from

        if context.date_to is not None:
            where_parts.append("uae.occurred_at <= :date_to")
            params["date_to"] = context.date_to

        role_filter = _safe_str(context.filters.get("role")).lower()
        if role_filter:
            where_parts.append("LOWER(COALESCE(uae.role_name, '')) = :role_name")
            params["role_name"] = role_filter

        action_filter = _safe_str(context.filters.get("action"))
        if action_filter:
            where_parts.append("COALESCE(uae.action, '') = :action")
            params["action"] = action_filter

        status_filter = _safe_str(context.filters.get("status")).lower()
        if status_filter:
            where_parts.append("LOWER(COALESCE(uae.status, '')) = :status")
            params["status"] = status_filter

        q = _safe_str(context.filters.get("q"))
        if q:
            where_parts.append(
                "("
                "COALESCE(uae.action, '') ILIKE :q OR "
                "COALESCE(uae.target_type, '') ILIKE :q OR "
                "COALESCE(uae.route, '') ILIKE :q OR "
                f"{user_name_sql} ILIKE :q OR "
                "COALESCE(u.email, '') ILIKE :q"
                ")"
            )
            params["q"] = f"%{q}%"

        sql = f"""
            SELECT
                uae.occurred_at AS occurred_at,
                {user_name_sql} AS user_name,
                COALESCE(u.email, '') AS user_email,
                LOWER(COALESCE(uae.role_name, 'unknown')) AS role,
                COALESCE(uae.action, '') AS action,
                COALESCE(uae.target_type, '') AS target_type,
                COALESCE(CAST(uae.target_id AS TEXT), '') AS target_id,
                LOWER(COALESCE(uae.status, '')) AS status,
                COALESCE(uae.route, '') AS route,
                COALESCE(uae.ip_address, '') AS ip_address
            FROM public.user_activity_events uae
            LEFT JOIN public.users u ON u.id = uae.user_id
            WHERE {" AND ".join(where_parts)}
            ORDER BY uae.occurred_at DESC
            LIMIT :limit
        """

        for row in _safe_mappings(session, sql, params):
            rows.append(
                {
                    "occurred_at": _iso(row.get("occurred_at")),
                    "user_name": _safe_str(row.get("user_name"), "Unknown"),
                    "user_email": _safe_str(row.get("user_email")),
                    "role": _safe_str(row.get("role"), "unknown"),
                    "action": _safe_str(row.get("action")),
                    "target_type": _safe_str(row.get("target_type")),
                    "target_id": _safe_str(row.get("target_id")),
                    "status": _safe_str(row.get("status")),
                    "route": _safe_str(row.get("route")),
                    "ip_address": _safe_str(row.get("ip_address")),
                }
            )

    # ---------------------------------------------------------------------
    # Fallback source: admin_audit_log
    # Useful when the richer activity table exists but is not populated enough,
    # or when this environment mainly records governance/admin activity.
    # ---------------------------------------------------------------------
    if not rows and _table_exists(session, "admin_audit_log"):
        where_parts = ["1=1"]
        params = {"limit": limit}

        if context.date_from is not None:
            where_parts.append("aal.created_at >= :date_from")
            params["date_from"] = context.date_from

        if context.date_to is not None:
            where_parts.append("aal.created_at <= :date_to")
            params["date_to"] = context.date_to

        q = _safe_str(context.filters.get("q"))
        if q:
            where_parts.append(
                "("
                "COALESCE(aal.action, '') ILIKE :q OR "
                "COALESCE(aal.entity_type, '') ILIKE :q OR "
                f"{user_name_sql} ILIKE :q OR "
                "COALESCE(u.email, '') ILIKE :q"
                ")"
            )
            params["q"] = f"%{q}%"

        sql = f"""
            SELECT
                aal.created_at AS occurred_at,
                {user_name_sql} AS user_name,
                COALESCE(u.email, '') AS user_email,
                'admin' AS role,
                COALESCE(aal.action, '') AS action,
                COALESCE(aal.entity_type, '') AS target_type,
                COALESCE(CAST(aal.entity_id AS TEXT), '') AS target_id,
                'success' AS status,
                '' AS route,
                '' AS ip_address
            FROM public.admin_audit_log aal
            LEFT JOIN public.users u ON u.id = aal.admin_id
            WHERE {" AND ".join(where_parts)}
            ORDER BY aal.created_at DESC
            LIMIT :limit
        """

        for row in _safe_mappings(session, sql, params):
            rows.append(
                {
                    "occurred_at": _iso(row.get("occurred_at")),
                    "user_name": _safe_str(row.get("user_name"), "Unknown"),
                    "user_email": _safe_str(row.get("user_email")),
                    "role": "admin",
                    "action": _safe_str(row.get("action")),
                    "target_type": _safe_str(row.get("target_type")),
                    "target_id": _safe_str(row.get("target_id")),
                    "status": "success",
                    "route": "",
                    "ip_address": "",
                }
            )

    summary = {
        "total_events": len(rows),
        "success_count": sum(1 for row in rows if row["status"] == "success"),
        "failed_count": sum(1 for row in rows if row["status"] == "failed"),
        "blocked_count": sum(1 for row in rows if row["status"] == "blocked"),
        "unique_actions": len({row["action"] for row in rows if row["action"]}),
        "unique_users": len({row["user_email"] for row in rows if row["user_email"]}),
    }

    return BuiltReport(
        context=context,
        columns=columns,
        rows=rows,
        summary=summary,
        filename_base=_build_filename_base(context.report_key, context.generated_at),
    )


def _build_product_lifecycle_report(session: Session, context: ReportContext) -> BuiltReport:
    columns = [
        "created_at",
        "product_id",
        "action",
        "actor_role",
        "actor_id",
        "notes",
    ]
    rows: List[Dict[str, Any]] = []

    if not _table_exists(session, "product_moderation_events"):
        raise ValueError("product_moderation_events table does not exist. Product lifecycle report cannot be generated.")

    where_parts = ["1=1"]
    params: Dict[str, Any] = {
        "limit": max(1, min(_safe_int(context.filters.get("limit"), 500), 5000))
    }

    if context.date_from is not None:
        where_parts.append("pme.created_at >= :date_from")
        params["date_from"] = context.date_from

    if context.date_to is not None:
        where_parts.append("pme.created_at <= :date_to")
        params["date_to"] = context.date_to

    action_filter = _safe_str(context.filters.get("action"))
    if action_filter:
        where_parts.append("COALESCE(pme.action, '') = :action")
        params["action"] = action_filter

    actor_role = _safe_str(context.filters.get("actor_role") or context.filters.get("role")).lower()
    if actor_role:
        where_parts.append("LOWER(COALESCE(pme.actor_role, '')) = :actor_role")
        params["actor_role"] = actor_role

    q = _safe_str(context.filters.get("q"))
    if q:
        where_parts.append(
            "("
            "COALESCE(pme.product_id, '') ILIKE :q OR "
            "COALESCE(pme.action, '') ILIKE :q OR "
            "COALESCE(pme.actor_role, '') ILIKE :q OR "
            "COALESCE(pme.notes, '') ILIKE :q"
            ")"
        )
        params["q"] = f"%{q}%"

    sql = f"""
        SELECT
            pme.created_at AS created_at,
            COALESCE(pme.product_id, '') AS product_id,
            COALESCE(pme.action, '') AS action,
            COALESCE(pme.actor_role, '') AS actor_role,
            COALESCE(pme.actor_id, '') AS actor_id,
            COALESCE(pme.notes, '') AS notes
        FROM public.product_moderation_events pme
        WHERE {" AND ".join(where_parts)}
        ORDER BY pme.created_at DESC
        LIMIT :limit
    """

    for row in _safe_mappings(session, sql, params):
        rows.append(
            {
                "created_at": _iso(row.get("created_at")),
                "product_id": _safe_str(row.get("product_id")),
                "action": _safe_str(row.get("action")),
                "actor_role": _safe_str(row.get("actor_role")),
                "actor_id": _safe_str(row.get("actor_id")),
                "notes": _safe_str(row.get("notes")),
            }
        )

    summary = {
        "total_events": len(rows),
        "submitted_count": sum(1 for row in rows if row["action"] == "submitted"),
        "approved_count": sum(1 for row in rows if row["action"] == "approved"),
        "rejected_count": sum(1 for row in rows if row["action"] == "rejected"),
        "resubmitted_count": sum(1 for row in rows if row["action"] == "resubmitted"),
        "unique_products": len({row["product_id"] for row in rows if row["product_id"]}),
    }

    return BuiltReport(
        context=context,
        columns=columns,
        rows=rows,
        summary=summary,
        filename_base=_build_filename_base(context.report_key, context.generated_at),
    )


def _build_product_search_statistics_report(session: Session, context: ReportContext) -> BuiltReport:
    period = context.period
    columns = [
        "bucket",
        "query",
        "search_count",
        "unique_users",
    ]
    rows: List[Dict[str, Any]] = []

    if not _table_exists(session, "customer_search_events"):
        raise ValueError("customer_search_events table does not exist. Search statistics report cannot be generated.")

    if period == "year":
        bucket_sql = "to_char(created_at, 'YYYY')"
    elif period == "week":
        bucket_sql = "to_char(date_trunc('week', created_at), 'YYYY-MM-DD')"
    elif period == "day":
        bucket_sql = "to_char(date_trunc('day', created_at), 'YYYY-MM-DD')"
    else:
        bucket_sql = "to_char(date_trunc('month', created_at), 'YYYY-MM')"

    where_parts = ["1=1"]
    params: Dict[str, Any] = {
        "limit": max(1, min(_safe_int(context.filters.get("limit"), 500), 5000))
    }

    if context.date_from is not None:
        where_parts.append("created_at >= :date_from")
        params["date_from"] = context.date_from

    if context.date_to is not None:
        where_parts.append("created_at <= :date_to")
        params["date_to"] = context.date_to

    q = _safe_str(context.filters.get("q"))
    if q:
        where_parts.append("query ILIKE :q")
        params["q"] = f"%{q}%"

    sql = f"""
        SELECT
            {bucket_sql} AS bucket,
            COALESCE(query, '') AS query,
            COUNT(*) AS search_count,
            COUNT(DISTINCT user_id) AS unique_users
        FROM public.customer_search_events
        WHERE {" AND ".join(where_parts)}
        GROUP BY bucket, query
        ORDER BY bucket DESC, search_count DESC, query ASC
        LIMIT :limit
    """

    for row in _safe_mappings(session, sql, params):
        rows.append(
            {
                "bucket": _safe_str(row.get("bucket")),
                "query": _safe_str(row.get("query")),
                "search_count": _safe_int(row.get("search_count")),
                "unique_users": _safe_int(row.get("unique_users")),
            }
        )

    summary = {
        "total_rows": len(rows),
        "total_searches": sum(_safe_int(row["search_count"]) for row in rows),
        "unique_queries": len({row["query"] for row in rows if row["query"]}),
        "period": period,
        "top_query": _safe_str(
            max(rows, key=lambda r: _safe_int(r["search_count"]), default={}).get("query")
        ),
    }

    return BuiltReport(
        context=context,
        columns=columns,
        rows=rows,
        summary=summary,
        filename_base=_build_filename_base(context.report_key, context.generated_at),
    )


def _build_moderation_sla_report(session: Session, context: ReportContext) -> BuiltReport:
    columns = [
        "product_id",
        "submitted_at",
        "reviewed_at",
        "review_hours",
        "final_action",
        "breached_sla",
    ]
    rows: List[Dict[str, Any]] = []

    if not _table_exists(session, "product_moderation_events"):
        raise ValueError("product_moderation_events table does not exist. Moderation SLA report cannot be generated.")

    sla_hours = max(1, min(_safe_int(context.filters.get("sla_hours"), 48), 240))

    where_parts = ["1=1"]
    params: Dict[str, Any] = {}

    if context.date_from is not None:
        where_parts.append("created_at >= :date_from")
        params["date_from"] = context.date_from

    if context.date_to is not None:
        where_parts.append("created_at <= :date_to")
        params["date_to"] = context.date_to

    sql = f"""
        SELECT
            COALESCE(product_id, '') AS product_id,
            LOWER(COALESCE(action, '')) AS action,
            created_at
        FROM public.product_moderation_events
        WHERE {" AND ".join(where_parts)}
        ORDER BY product_id ASC, created_at ASC
    """

    lifecycle_by_product: Dict[str, Dict[str, Any]] = {}

    for row in _safe_mappings(session, sql, params):
        product_id = _safe_str(row.get("product_id"))
        if not product_id:
            continue

        action = _safe_str(row.get("action")).lower()
        created_at = row.get("created_at")

        state = lifecycle_by_product.setdefault(
            product_id,
            {
                "submitted_at": None,
                "reviewed_at": None,
                "final_action": None,
            },
        )

        if action in {"submitted", "resubmitted", "updated_pending"}:
            state["submitted_at"] = created_at

        if action in {"approved", "rejected"}:
            state["reviewed_at"] = created_at
            state["final_action"] = action

    for product_id, state in lifecycle_by_product.items():
        submitted_at = state.get("submitted_at")
        reviewed_at = state.get("reviewed_at")
        final_action = _safe_str(state.get("final_action"))
        review_hours: Optional[float] = None
        breached = False

        if submitted_at is not None and reviewed_at is not None:
            try:
                elapsed_hours = (reviewed_at - submitted_at).total_seconds() / 3600.0
                review_hours = float(elapsed_hours)
                breached = review_hours > float(sla_hours)
            except Exception:
                review_hours = None
                breached = False

        if reviewed_at is not None:
            rows.append(
                {
                    "product_id": product_id,
                    "submitted_at": _iso(submitted_at),
                    "reviewed_at": _iso(reviewed_at),
                    "review_hours": round(review_hours, 2) if review_hours is not None else None,
                    "final_action": final_action,
                    "breached_sla": "yes" if breached else "no",
                }
            )

    reviewed_rows = [row for row in rows if row.get("reviewed_at")]
    breach_rows = [row for row in reviewed_rows if row.get("breached_sla") == "yes"]
    hour_values = [float(row["review_hours"]) for row in reviewed_rows if row.get("review_hours") is not None]

    summary = {
        "reviewed_count": len(reviewed_rows),
        "breached_count": len(breach_rows),
        "avg_review_hours": round(sum(hour_values) / len(hour_values), 2) if hour_values else 0.0,
        "sla_hours": sla_hours,
        "breach_rate_pct": round((len(breach_rows) / len(reviewed_rows)) * 100, 2) if reviewed_rows else 0.0,
    }

    return BuiltReport(
        context=context,
        columns=columns,
        rows=rows,
        summary=summary,
        filename_base=_build_filename_base(context.report_key, context.generated_at),
    )


# ----------------------------------------------------------------------------
# Report dispatcher
# ----------------------------------------------------------------------------
def _run_report_builder(*, session: Session, normalized_key: str, context: ReportContext) -> BuiltReport:
    if normalized_key == "auth_activity":
        return _build_auth_activity_report(session, context)
    if normalized_key == "user_activity":
        return _build_user_activity_report(session, context)
    if normalized_key == "product_lifecycle":
        return _build_product_lifecycle_report(session, context)
    if normalized_key == "product_search_statistics":
        return _build_product_search_statistics_report(session, context)
    if normalized_key == "moderation_sla":
        return _build_moderation_sla_report(session, context)

    raise ValueError(f"Unhandled report_key: {normalized_key}")


def _should_auto_expand_standard_window(*, normalized_key: str, context: ReportContext, built: BuiltReport) -> bool:
    if built.rows:
        return False

    recommended_days = AUTO_EXPAND_STANDARD_DAYS.get(normalized_key, 0)
    if recommended_days <= 0:
        return False

    preset = _safe_str(context.filters.get("preset"), "").lower()
    if preset != "standard":
        return False

    if context.filters.get("date_from") or context.filters.get("date_to"):
        return False

    requested_days = _safe_int(context.filters.get("days"), 0)
    if requested_days <= 0 or requested_days >= recommended_days:
        return False

    return True


def _auto_expand_standard_window(
    *,
    session: Session,
    normalized_key: str,
    context: ReportContext,
    built: BuiltReport,
) -> BuiltReport:
    if not _should_auto_expand_standard_window(normalized_key=normalized_key, context=context, built=built):
        return built

    requested_days = _safe_int(context.filters.get("days"), 0)
    effective_days = AUTO_EXPAND_STANDARD_DAYS.get(normalized_key, requested_days)

    expanded_filters = dict(context.filters)
    expanded_filters["requested_days"] = requested_days
    expanded_filters["auto_expanded_from_days"] = requested_days
    expanded_filters["days"] = effective_days
    expanded_filters["window_strategy"] = "auto_expanded_standard_window"

    expanded_from, expanded_to = _date_window_from_filters(expanded_filters)
    expanded_context = replace(
        context,
        date_from=expanded_from,
        date_to=expanded_to,
        filters=expanded_filters,
    )

    rebuilt = _run_report_builder(session=session, normalized_key=normalized_key, context=expanded_context)
    rebuilt.summary = dict(rebuilt.summary or {})
    rebuilt.summary["window_auto_expanded"] = True
    rebuilt.summary["requested_days"] = requested_days
    rebuilt.summary["effective_days"] = effective_days
    rebuilt.summary["window_note"] = (
        f"No rows were found in the requested last {requested_days} days. "
        f"The standard report window was expanded automatically to the last {effective_days} days."
    )
    return rebuilt


def build_report(
    *,
    session: Session,
    report_key: str,
    generated_by_name: str,
    generated_by_email: Optional[str] = None,
    export_format: str = "pdf",
    filters: Optional[Dict[str, Any]] = None,
) -> BuiltReport:
    normalized_key = _safe_str(report_key).lower()
    filters = dict(filters or {})
    generated_at = datetime.utcnow()
    period = _normalize_period(filters.get("period"))
    date_from, date_to = _date_window_from_filters(filters)

    titles = {
        "auth_activity": (
            "Authentication Activity Report",
            "Login, logout, refresh, and failed authentication activity.",
        ),
        "user_activity": (
            "User Activity Report",
            "System activity performed by registered users after login.",
        ),
        "product_lifecycle": (
            "Product Lifecycle Report",
            "Product submissions, moderation actions, and lifecycle activity.",
        ),
        "product_search_statistics": (
            "Product Search Statistics Report",
            "Search behaviour grouped by the selected reporting period.",
        ),
        "moderation_sla": (
            "Moderation SLA Report",
            "Submission-to-review turnaround and SLA breach analysis.",
        ),
    }

    if normalized_key not in titles:
        raise ValueError(f"Unsupported report_key: {normalized_key}")

    title, subtitle = titles[normalized_key]

    context = ReportContext(
        report_key=normalized_key,
        title=title,
        subtitle=subtitle,
        generated_at=generated_at,
        generated_by_name=_safe_str(generated_by_name, "Administrator"),
        generated_by_email=_safe_str(generated_by_email) or None,
        export_format=_safe_str(export_format, "pdf").lower(),
        period=period,
        date_from=date_from,
        date_to=date_to,
        filters=filters,
    )

    built = _run_report_builder(session=session, normalized_key=normalized_key, context=context)
    built = _auto_expand_standard_window(
        session=session,
        normalized_key=normalized_key,
        context=context,
        built=built,
    )
    return built


# ----------------------------------------------------------------------------
# Dashboard-style chart helpers for PDF
# ----------------------------------------------------------------------------
def _time_distribution(report: BuiltReport) -> List[Tuple[str, float]]:
    period = report.context.period
    counter: Dict[str, float] = defaultdict(float)

    if report.context.report_key == "product_search_statistics":
        for row in report.rows:
            bucket = _safe_str(row.get("bucket"))
            if bucket:
                counter[bucket] += _safe_float(row.get("search_count"), 0.0)
        return _top_n(counter, 8)

    if report.context.report_key == "moderation_sla":
        for row in report.rows:
            bucket = _bucket_from_iso(_safe_str(row.get("reviewed_at")), period)
            if bucket:
                counter[bucket] += 1.0
        return _top_n(counter, 8)

    for row in report.rows:
        ts = row.get("occurred_at") or row.get("created_at") or row.get("submitted_at")
        bucket = _bucket_from_iso(_safe_str(ts), period)
        if bucket:
            counter[bucket] += 1.0

    return _top_n(counter, 8)


def _category_distribution(
    report: BuiltReport,
    field: str,
    value_field: Optional[str] = None,
) -> List[Tuple[str, float]]:
    counter: Dict[str, float] = defaultdict(float)

    for row in report.rows:
        key = _safe_str(row.get(field))
        if not key:
            continue
        if value_field is None:
            counter[key] += 1.0
        else:
            counter[key] += _safe_float(row.get(value_field), 0.0)

    return _top_n(counter, 6)


def _report_chart_payloads(report: BuiltReport) -> List[Dict[str, Any]]:
    key = report.context.report_key

    if key == "auth_activity":
        return [
            {"title": "Auth Events by Period", "kind": "line", "series": _time_distribution(report)},
            {"title": "Event Type Distribution", "kind": "bar", "series": _category_distribution(report, "event_type")},
            {"title": "Role Distribution", "kind": "bar", "series": _category_distribution(report, "role")},
            {"title": "Top Users by Events", "kind": "bar", "series": _category_distribution(report, "user_name")},
        ]

    if key == "user_activity":
        return [
            {"title": "Activity by Period", "kind": "line", "series": _time_distribution(report)},
            {"title": "Action Distribution", "kind": "bar", "series": _category_distribution(report, "action")},
            {"title": "Role Distribution", "kind": "bar", "series": _category_distribution(report, "role")},
            {"title": "Status Distribution", "kind": "bar", "series": _category_distribution(report, "status")},
        ]

    if key == "product_lifecycle":
        return [
            {"title": "Lifecycle Events by Period", "kind": "line", "series": _time_distribution(report)},
            {"title": "Lifecycle Action Mix", "kind": "bar", "series": _category_distribution(report, "action")},
            {"title": "Actor Role Mix", "kind": "bar", "series": _category_distribution(report, "actor_role")},
            {"title": "Top Products by Events", "kind": "bar", "series": _category_distribution(report, "product_id")},
        ]

    if key == "product_search_statistics":
        return [
            {"title": "Searches by Period", "kind": "line", "series": _category_distribution(report, "bucket", "search_count")},
            {"title": "Top Queries", "kind": "bar", "series": _category_distribution(report, "query", "search_count")},
            {"title": "Unique Users by Period", "kind": "bar", "series": _category_distribution(report, "bucket", "unique_users")},
            {"title": "Query Reach", "kind": "bar", "series": _category_distribution(report, "query", "unique_users")},
        ]

    if key == "moderation_sla":
        return [
            {"title": "Reviewed by Period", "kind": "line", "series": _time_distribution(report)},
            {"title": "Final Action Mix", "kind": "bar", "series": _category_distribution(report, "final_action")},
            {"title": "Breach Distribution", "kind": "bar", "series": _category_distribution(report, "breached_sla")},
            {"title": "Review Hours by Product", "kind": "bar", "series": _category_distribution(report, "product_id", "review_hours")},
        ]

    return []


def _fit_detail_col_widths(page_width: float, columns: Sequence[str]) -> List[float]:
    """
    Give deterministic widths so wide admin tables render cleanly in PDF.
    """
    col_count = max(1, len(columns))
    usable = max(300.0, page_width - 8.0)

    preferred: Dict[str, float] = {
        "occurred_at": 78.0,
        "created_at": 78.0,
        "submitted_at": 78.0,
        "reviewed_at": 78.0,
        "user_name": 88.0,
        "user_email": 118.0,
        "role": 48.0,
        "event_type": 62.0,
        "action": 88.0,
        "target_type": 66.0,
        "target_id": 78.0,
        "status": 52.0,
        "route": 112.0,
        "ip_address": 62.0,
        "user_agent": 140.0,
        "product_id": 78.0,
        "query": 130.0,
        "bucket": 70.0,
        "notes": 150.0,
        "review_hours": 60.0,
        "final_action": 70.0,
        "breached_sla": 64.0,
        "search_count": 68.0,
        "unique_users": 72.0,
        "actor_role": 64.0,
        "actor_id": 78.0,
    }

    widths = [preferred.get(str(col), 78.0) for col in columns]
    total = sum(widths)

    if total > usable:
        scale = usable / total
        widths = [max(44.0, w * scale) for w in widths]

    total = sum(widths)
    if total < usable and col_count > 0:
        extra = (usable - total) / col_count
        widths = [w + extra for w in widths]

    return widths


# ----------------------------------------------------------------------------
# PDF export (professional layout)
# ----------------------------------------------------------------------------
def _pdf_bytes_dashboard_with_reportlab(report: BuiltReport) -> bytes:
    from reportlab.graphics.shapes import Drawing, Line, PolyLine, Rect, String  # type: ignore[import-not-found]
    from reportlab.lib import colors  # type: ignore[import-not-found]
    from reportlab.lib.pagesizes import A4, landscape  # type: ignore[import-not-found]
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # type: ignore[import-not-found]
    from reportlab.lib.units import mm  # type: ignore[import-not-found]
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle  # type: ignore[import-not-found]

    page_w, _page_h = landscape(A4)

    theme: Dict[str, Any] = {
        "bg": colors.HexColor("#F5F8FA"),
        "ink": colors.HexColor("#1F2937"),
        "muted": colors.HexColor("#64748B"),
        "teal": colors.HexColor("#2A7F8B"),
        "border": colors.HexColor("#DCE5EA"),
        "card": colors.white,
        "grid": colors.HexColor("#E5E7EB"),
    }

    styles = getSampleStyleSheet()
    if "ReportTitleBig" not in styles.byName:
        styles.add(
            ParagraphStyle(
                name="ReportTitleBig",
                fontName="Helvetica-Bold",
                fontSize=22,
                leading=26,
                textColor=theme["ink"],
                spaceAfter=2,
            )
        )
    if "ReportSubtle" not in styles.byName:
        styles.add(
            ParagraphStyle(
                name="ReportSubtle",
                fontName="Helvetica",
                fontSize=9,
                leading=12,
                textColor=theme["muted"],
            )
        )
    if "ReportPill" not in styles.byName:
        styles.add(
            ParagraphStyle(
                name="ReportPill",
                fontName="Helvetica-Bold",
                fontSize=9,
                leading=11,
                textColor=theme["ink"],
            )
        )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=10 * mm,
        rightMargin=10 * mm,
        topMargin=10 * mm,
        bottomMargin=12 * mm,
    )

    story: List[Any] = []
    ctx = report.context

    generated_by = ctx.generated_by_name
    if ctx.generated_by_email:
        generated_by = f"{generated_by}<br/><font size='8'>{ctx.generated_by_email}</font>"

    date_pill = (
        f"{ctx.period.title()} Report"
        + (
            f" • {ctx.date_from.strftime('%d %b %Y') if ctx.date_from else 'Start'}"
            f" - {ctx.date_to.strftime('%d %b %Y') if ctx.date_to else 'Now'}"
        )
    )

    header_left = [
        Paragraph("AgroConnect Namibia", styles["ReportSubtle"]),
        Paragraph(ctx.title, styles["ReportTitleBig"]),
        Paragraph(ctx.subtitle, styles["ReportSubtle"]),
    ]

    header_right = Table(
        [
            [Paragraph(f"<b>{date_pill}</b>", styles["ReportPill"])],
            [
                Paragraph(
                    f"<b>Generated by</b><br/>{generated_by}<br/><b>Generated at</b><br/>{ctx.generated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
                    styles["ReportSubtle"],
                )
            ],
        ],
        colWidths=[75 * mm],
    )
    header_right.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.8, theme["border"]),
                ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                ("PADDING", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )

    header_table = Table(
        [[header_left, header_right]],
        colWidths=[page_w - doc.leftMargin - doc.rightMargin - 80 * mm, 80 * mm],
    )
    header_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
                ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    story.append(header_table)
    story.append(Spacer(1, 6))

    filter_line = _filters_line(ctx.filters)
    if filter_line:
        filter_table = Table([[Paragraph(f"<b>Filters:</b> {filter_line}", styles["ReportSubtle"])]])
        filter_table.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.6, theme["border"]),
                    ("BACKGROUND", (0, 0), (-1, -1), colors.white),
                    ("PADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        story.append(filter_table)
        story.append(Spacer(1, 6))

    summary_items = list(report.summary.items())[:6]
    if not summary_items:
        summary_items = [("total_rows", len(report.rows))]

    def _summary_card(title: str, value: Any) -> Table:
        card = Table(
            [
                [Paragraph(f"<b>{_safe_str(title).replace('_', ' ').title()}</b>", styles["ReportSubtle"])],
                [Paragraph(f"<b><font size='18'>{_safe_str(value)}</font></b>", styles["Heading2"])],
            ],
            colWidths=[58 * mm],
            rowHeights=[9 * mm, 12 * mm],
        )
        card.setStyle(
            TableStyle(
                [
                    ("BOX", (0, 0), (-1, -1), 0.8, theme["border"]),
                    ("BACKGROUND", (0, 0), (-1, -1), theme["card"]),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.4, theme["grid"]),
                ]
            )
        )
        return card

    summary_cards = [_summary_card(k, v) for k, v in summary_items[:3]]
    while len(summary_cards) < 3:
        summary_cards.append(_summary_card("—", "—"))

    kpi_table = Table([summary_cards], colWidths=[60 * mm, 60 * mm, 60 * mm])
    kpi_table.setStyle(
        TableStyle(
            [
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 3),
                ("RIGHTPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    story.append(kpi_table)
    story.append(Spacer(1, 8))

    chart_defs = _report_chart_payloads(report)[:4]

    def _chart_panel(title: str, series: List[Tuple[str, float]], kind: str = "bar") -> Drawing:
        width = 122 * mm
        height = 65 * mm
        drawing = Drawing(width, height)

        panel = Rect(0, 0, width, height, 8, 8)
        panel.fillColor = colors.white
        panel.strokeColor = theme["border"]
        panel.strokeWidth = 0.8
        drawing.add(panel)

        title_text = String(8, height - 12, _safe_str(title))
        title_text.fontName = "Helvetica-Bold"
        title_text.fontSize = 9
        title_text.fillColor = theme["ink"]
        drawing.add(title_text)

        if not series:
            empty_text = String(8, height / 2, "No data available")
            empty_text.fontName = "Helvetica"
            empty_text.fontSize = 9
            empty_text.fillColor = theme["muted"]
            drawing.add(empty_text)
            return drawing

        plot_x = 10
        plot_y = 12
        plot_w = width - 22
        plot_h = height - 28

        axis_y = Line(plot_x, plot_y, plot_x, plot_y + plot_h)
        axis_y.strokeColor = theme["grid"]
        axis_y.strokeWidth = 0.7
        drawing.add(axis_y)

        axis_x = Line(plot_x, plot_y, plot_x + plot_w, plot_y)
        axis_x.strokeColor = theme["grid"]
        axis_x.strokeWidth = 0.7
        drawing.add(axis_x)

        labels = [_compact_label(label, 14) for label, _ in series[:6]]
        values = [max(0.0, float(val)) for _, val in series[:6]]
        max_value = max(values) if values else 1.0
        if max_value <= 0:
            max_value = 1.0

        if kind == "line":
            points: List[float] = []
            step_x = plot_w / max(1, len(values) - 1) if len(values) > 1 else plot_w / 2
            for idx, val in enumerate(values):
                px = plot_x + (idx * step_x if len(values) > 1 else plot_w / 2)
                py = plot_y + (val / max_value) * (plot_h - 10)
                points.extend([px, py])

                label_obj = String(px - 8, plot_y - 10, labels[idx])
                label_obj.fontName = "Helvetica"
                label_obj.fontSize = 6.5
                label_obj.fillColor = theme["muted"]
                drawing.add(label_obj)

            if len(points) >= 4:
                line = PolyLine(points)
                line.strokeColor = theme["teal"]
                line.strokeWidth = 1.6
                drawing.add(line)
        else:
            bar_gap = 4
            bar_w = max(10, (plot_w - (bar_gap * (len(values) + 1))) / max(1, len(values)))
            for idx, val in enumerate(values):
                bar_h = (val / max_value) * (plot_h - 8)
                bar_x = plot_x + bar_gap + idx * (bar_w + bar_gap)
                bar_y = plot_y

                bar = Rect(bar_x, bar_y, bar_w, bar_h)
                bar.fillColor = theme["teal"]
                bar.strokeColor = theme["teal"]
                drawing.add(bar)

                label_obj = String(bar_x, plot_y - 10, labels[idx])
                label_obj.fontName = "Helvetica"
                label_obj.fontSize = 6.2
                label_obj.fillColor = theme["muted"]
                drawing.add(label_obj)

        return drawing

    chart_panels = []
    for chart_def in chart_defs:
        chart_panels.append(
            _chart_panel(
                _safe_str(chart_def.get("title")),
                chart_def.get("series") or [],
                _safe_str(chart_def.get("kind"), "bar"),
            )
        )

    while len(chart_panels) < 4:
        chart_panels.append(_chart_panel("No chart", [], "bar"))

    chart_grid = Table(
        [
            [chart_panels[0], chart_panels[1]],
            [chart_panels[2], chart_panels[3]],
        ],
        colWidths=[125 * mm, 125 * mm],
    )
    chart_grid.setStyle(
        TableStyle(
            [
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 2),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]
        )
    )
    story.append(chart_grid)
    story.append(Spacer(1, 8))

    # ------------------------------------------------------------------------
    # Detail table
    # ------------------------------------------------------------------------
    max_pdf_rows = max(1, min(len(report.rows), 60))
    detail_rows: List[List[str]] = [report.columns]

    for row in report.rows[:max_pdf_rows]:
        detail_rows.append([_safe_str(row.get(col)) for col in report.columns])

    if len(detail_rows) == 1:
        detail_rows.append(
            ["No records found for the selected filter set."] + [""] * (len(report.columns) - 1)
        )

    usable_table_width = page_w - doc.leftMargin - doc.rightMargin
    detail_col_widths = _fit_detail_col_widths(usable_table_width, report.columns)

    detail_table = Table(detail_rows, repeatRows=1, colWidths=detail_col_widths)
    detail_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), theme["teal"]),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 8.0),
                ("FONTSIZE", (0, 1), (-1, -1), 7.0),
                ("GRID", (0, 0), (-1, -1), 0.25, theme["border"]),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, theme["bg"]]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("WORDWRAP", (0, 0), (-1, -1), "CJK"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]
        )
    )
    story.append(detail_table)

    if len(report.rows) > max_pdf_rows:
        story.append(Spacer(1, 6))
        story.append(
            Paragraph(
                f"Showing first {max_pdf_rows} detail rows out of {len(report.rows)} total rows in the PDF export.",
                styles["ReportSubtle"],
            )
        )

    def _page_decor(canvas_obj: Any, doc_obj: Any) -> None:
        canvas_obj.saveState()
        canvas_obj.setFillColor(theme["muted"])
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.drawString(doc.leftMargin, 7 * mm, f"AgroConnect Namibia • {ctx.title}")
        canvas_obj.drawRightString(page_w - doc.rightMargin, 7 * mm, f"Page {doc_obj.page}")
        canvas_obj.restoreState()

    doc.build(story, onFirstPage=_page_decor, onLaterPages=_page_decor)
    return buffer.getvalue()


def _simple_pdf_bytes(report: BuiltReport) -> bytes:
    """
    Very small fallback PDF used only when ReportLab is unavailable.
    """
    lines: List[str] = []
    ctx = report.context

    lines.append("AgroConnect Namibia")
    lines.append(ctx.title)
    lines.append(ctx.subtitle)
    lines.append("")
    lines.append(
        f"Generated by: {ctx.generated_by_name}"
        + (f" ({ctx.generated_by_email})" if ctx.generated_by_email else "")
    )
    lines.append(f"Generated at (UTC): {ctx.generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Period: {ctx.period}")
    lines.append(f"Date from: {ctx.date_from.strftime('%Y-%m-%d %H:%M:%S') if ctx.date_from else '—'}")
    lines.append(f"Date to: {ctx.date_to.strftime('%Y-%m-%d %H:%M:%S') if ctx.date_to else '—'}")

    filter_line = _filters_line(ctx.filters)
    if filter_line:
        lines.append(f"Filters: {filter_line}")

    lines.append("")
    lines.append("Summary:")
    for key, value in report.summary.items():
        lines.append(f"- {_safe_str(key).replace('_', ' ').title()}: {value}")

    lines.append("")
    lines.append("Details:")
    lines.append(" | ".join(report.columns))
    for row in report.rows[:350]:
        lines.append(" | ".join(_safe_str(row.get(col)) for col in report.columns))

    content: List[str] = []
    content.append("BT")
    content.append("/F1 9 Tf")
    content.append("48 810 Td")
    for line in lines:
        safe_line = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        content.append(f"({safe_line}) Tj")
        content.append("0 -13 Td")
    content.append("ET")

    stream = "\n".join(content).encode("utf-8")
    objects: List[bytes] = []
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj")
    objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj")
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 842 595] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj"
    )
    objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj")
    objects.append(b"5 0 obj << /Length %d >> stream\n" % len(stream) + stream + b"\nendstream endobj")

    out = io.BytesIO()
    out.write(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(out.tell())
        out.write(obj + b"\n")

    xref_pos = out.tell()
    out.write(b"xref\n0 %d\n" % (len(objects) + 1))
    out.write(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.write(f"{off:010d} 00000 n \n".encode("ascii"))

    out.write(b"trailer << /Size %d /Root 1 0 R >>\n" % (len(objects) + 1))
    out.write(b"startxref\n")
    out.write(str(xref_pos).encode("ascii") + b"\n%%EOF")
    return out.getvalue()


def pdf_bytes(report: BuiltReport) -> bytes:
    """
    Keep the professional PDF unless ReportLab is missing.
    Do not silently hide real render problems behind the plain fallback PDF.
    """
    try:
        return _pdf_bytes_dashboard_with_reportlab(report)
    except ImportError:
        logger.warning("ReportLab is not installed. Falling back to simple PDF export.")
        return _simple_pdf_bytes(report)


# ----------------------------------------------------------------------------
# Public export API
# ----------------------------------------------------------------------------
def export_report_bytes(
    *,
    session: Session,
    report_key: str,
    export_format: str,
    generated_by_name: str,
    generated_by_email: Optional[str] = None,
    filters: Optional[Dict[str, Any]] = None,
) -> Tuple[bytes, str, str, BuiltReport]:
    report = build_report(
        session=session,
        report_key=report_key,
        generated_by_name=generated_by_name,
        generated_by_email=generated_by_email,
        export_format=export_format,
        filters=filters or {},
    )

    normalized_format = _safe_str(export_format, "pdf").lower()
    if normalized_format == "csv":
        payload = _csv_bytes(report.columns, report.rows, report)
        return payload, "text/csv; charset=utf-8", f"{report.filename_base}.csv", report

    payload = pdf_bytes(report)
    return payload, "application/pdf", f"{report.filename_base}.pdf", report


SUPPORTED_REPORT_KEYS: Tuple[str, ...] = (
    "auth_activity",
    "user_activity",
    "product_lifecycle",
    "product_search_statistics",
    "moderation_sla",
)