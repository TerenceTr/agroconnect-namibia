# ============================================================================
# backend/routes/admin_reports.py — Admin Analytics & Reporting (Admin-only)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Thin Flask route layer for Admin analytics + standard/ad hoc reporting.
#
# IMPORTANT:
#   • Export name MUST be `admin_reports_bp`
#   • Do NOT set url_prefix here (registry attaches /api/admin/reports)
#
# ROUTES:
#   Existing:
#     GET  /overview
#     GET  /presence
#     GET  /audit-overview
#     GET  /moderation-sla
#     GET  /export                        (legacy compatibility)
#
#   New reporting routes:
#     GET  /catalog
#     POST /generate
#     GET  /generate                      (query-string version)
#     POST /generate/export
#     GET  /generate/export               (query-string version)
#
# SETTINGS INTEGRATION:
#   ✅ Uses DEFAULT_REPORT_DAYS from app.config when days is not supplied
#   ✅ Uses REPORT_PREVIEW_ROWS from app.config for preview defaults
#   ✅ Uses PRODUCT_REVIEW_SLA_HOURS from app.config for SLA defaults
#   ✅ Respects SEARCH_ANALYTICS_ENABLED when generating/exporting search reports
#
# DESIGN GOALS:
#   ✅ Standard report generation
#   ✅ Ad hoc filtered report generation
#   ✅ Professional CSV/PDF export path
#   ✅ Keeps older report/export endpoints working
#   ✅ Writes admin report usage into user_activity_events
# ============================================================================
from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

from flask.blueprints import Blueprint
from flask.globals import current_app, g, request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.database.db import db
from backend.services.audit_logger import AuditLogger
from backend.services.admin_reports.overview import build_admin_overview
from backend.services.admin_reports.presence import build_admin_presence
from backend.services.admin_reports.report_exporter import (
    SUPPORTED_REPORT_KEYS,
    build_report,
    export_report_bytes,
)

# Admin auth decorators (best effort)
try:
    from backend.security import require_admin  # centralized RBAC
except Exception:
    def require_admin(fn):  # type: ignore
        return fn

try:
    from backend.utils.require_auth import require_access_token  # token required
except Exception:
    def require_access_token(fn):  # type: ignore
        return fn

try:
    from backend.models.product import Product  # type: ignore
except Exception:
    Product = None  # type: ignore

try:
    from backend.models.user import User  # type: ignore
except Exception:
    User = None  # type: ignore


admin_reports_bp = Blueprint("admin_reports", __name__)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------
def _json(payload: Dict[str, Any], status: int = 200) -> Response:
    """Return a real Flask Response object with status code attached."""
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _json_error(message: str, *, status: int = 400, details: Optional[Any] = None) -> Response:
    payload: Dict[str, Any] = {"success": False, "error": message}
    if details not in (None, "", [], {}):
        payload["details"] = details
    return _json(payload, status)


# ---------------------------------------------------------------------------
# Small config / parsing helpers
# ---------------------------------------------------------------------------
def _cfg_int(name: str, default: int) -> int:
    try:
        return int(current_app.config.get(name, default))
    except Exception:
        return default


def _cfg_bool(name: str, default: bool) -> bool:
    value = current_app.config.get(name, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _default_report_days() -> int:
    return max(7, min(365, _cfg_int("DEFAULT_REPORT_DAYS", 90)))


def _default_preview_rows() -> int:
    return max(5, min(200, _cfg_int("REPORT_PREVIEW_ROWS", 25)))


def _default_sla_hours() -> int:
    return max(1, min(240, _cfg_int("PRODUCT_REVIEW_SLA_HOURS", 48)))


def _int_qp(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = request.args.get(name)
    try:
        value = int(str(raw).strip())
    except Exception:
        value = int(default)
    return max(min_v, min(max_v, value))


def _truthy(name: str) -> bool:
    return request.args.get(name, "0").strip().lower() in ("1", "true", "yes")


def _safe_str(value: Any, default: Optional[str] = None) -> Optional[str]:
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


def _month_start(d: date) -> date:
    return date(d.year, d.month, 1)


def _add_months(d: date, months: int) -> date:
    y = d.year + (d.month - 1 + months) // 12
    m = (d.month - 1 + months) % 12 + 1
    return date(y, m, 1)


def _bucket_months(span: int) -> List[Tuple[date, date]]:
    """
    Returns monthly buckets [(start,end), ...], oldest -> newest.
    span=6 -> last 6 months.
    """
    today = date.today()
    end = _add_months(_month_start(today), 1)
    start = _add_months(_month_start(today), -(span - 1))

    buckets: List[Tuple[date, date]] = []
    cur = start
    while cur < end:
        nxt = _add_months(cur, 1)
        buckets.append((cur, nxt))
        cur = nxt
    return buckets


def _duration_hours(start_dt: Optional[datetime], end_dt: Optional[datetime]) -> Optional[float]:
    if not start_dt or not end_dt:
        return None
    try:
        return (end_dt - start_dt).total_seconds() / 3600.0
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Current admin helpers
# ---------------------------------------------------------------------------
def _current_user() -> Optional[Any]:
    user = getattr(g, "current_user", None)
    if user is not None:
        return user

    user2 = getattr(request, "current_user", None)
    if user2 is not None:
        return user2

    return None


def _current_admin_uuid() -> Optional[uuid.UUID]:
    user = _current_user()
    if user is None:
        return None

    raw = getattr(user, "id", None) or getattr(user, "user_id", None)
    if raw is None:
        return None

    if isinstance(raw, uuid.UUID):
        return raw

    try:
        return uuid.UUID(str(raw))
    except Exception:
        return None


def _current_admin_role_name() -> str:
    user = _current_user()
    if user is None:
        return "admin"

    role_name = getattr(user, "role_name", None)
    if isinstance(role_name, str) and role_name.strip():
        return role_name.strip().lower()

    role_raw = getattr(user, "role", None)
    try:
        role_int = int(role_raw) if role_raw is not None else 1
    except Exception:
        role_int = 1

    return {1: "admin", 2: "farmer", 3: "customer"}.get(role_int, "admin")


def _current_admin_name() -> str:
    user = _current_user()
    if user is None:
        return "Administrator"

    for attr in ("full_name", "name", "username"):
        value = _safe_str(getattr(user, attr, None))
        if value:
            return value

    email = _safe_str(getattr(user, "email", None))
    return email or "Administrator"


def _current_admin_email() -> Optional[str]:
    user = _current_user()
    if user is None:
        return None
    return _safe_str(getattr(user, "email", None))


# ---------------------------------------------------------------------------
# Request metadata helpers
# ---------------------------------------------------------------------------
def _request_session_id() -> Optional[str]:
    header_value = (
        request.headers.get("X-Session-ID")
        or request.headers.get("X-Client-Session")
        or request.headers.get("X-Device-Session")
    )
    if header_value:
        return str(header_value).strip()[:128] or None

    body = request.get_json(silent=True) or {}
    if isinstance(body, dict):
        raw = body.get("sessionId") or body.get("session_id")
        if raw is not None:
            return str(raw).strip()[:128] or None

    return None


def _client_ip() -> Optional[str]:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()[:64] or None
    return request.remote_addr or None


def _user_agent() -> Optional[str]:
    ua = request.headers.get("User-Agent")
    return ua[:256] if ua else None


# ---------------------------------------------------------------------------
# Audit wrapper
# ---------------------------------------------------------------------------
def _audit_admin_view(
    *,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[Any] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Report usage is activity, not governance.
    """
    admin_uuid = _current_admin_uuid()
    if admin_uuid is None:
        return

    try:
        AuditLogger.log_user_activity(
            user_id=admin_uuid,
            role_name=_current_admin_role_name(),
            action=action,
            target_type=target_type,
            target_id=target_id,
            session_id=_request_session_id(),
            route=request.path,
            http_method=request.method,
            ip_address=_client_ip(),
            user_agent=_user_agent(),
            metadata_json=metadata or {},
        )
    except TypeError:
        try:
            AuditLogger.log_user_activity(
                user_id=admin_uuid,
                role_name=_current_admin_role_name(),
                action=action,
                target_type=target_type,
                target_id=target_id,
                session_id=_request_session_id(),
                route=request.path,
                http_method=request.method,
                ip_address=_client_ip(),
                user_agent=_user_agent(),
                metadata=metadata or {},
            )
        except Exception:
            pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Request / report helpers
# ---------------------------------------------------------------------------
def _request_payload() -> Dict[str, Any]:
    if request.method == "GET":
        return dict(request.args)

    body = request.get_json(silent=True) or {}
    return body if isinstance(body, dict) else {}


def _normalized_report_key(raw: Any) -> str:
    key = (_safe_str(raw) or "").strip().lower()

    legacy_map = {
        "moderation_sla": "moderation_sla",
        "moderation-sla": "moderation_sla",
        "auth": "auth_activity",
        "auth_activity": "auth_activity",
        "user_activity": "user_activity",
        "activity": "user_activity",
        "product_lifecycle": "product_lifecycle",
        "product-lifecycle": "product_lifecycle",
        "product_search_statistics": "product_search_statistics",
        "product-search-statistics": "product_search_statistics",
        "search": "product_search_statistics",
    }
    return legacy_map.get(key, key)


def _collect_report_filters(source: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a clean filter object for report generation/export.
    Supports both standard and ad hoc generation.
    """
    filters: Dict[str, Any] = {}

    passthrough_keys = (
        "period",
        "span",
        "days",
        "date_from",
        "date_to",
        "from",
        "to",
        "q",
        "role",
        "action",
        "status",
        "event_type",
        "actor_role",
        "limit",
        "sla_hours",
    )

    for key in passthrough_keys:
        value = source.get(key)
        if value not in (None, "", [], {}):
            filters[key] = value

    # Normalize aliases
    if "from" in filters and "date_from" not in filters:
        filters["date_from"] = filters.pop("from")
    if "to" in filters and "date_to" not in filters:
        filters["date_to"] = filters.pop("to")

    # Standard presets
    preset = (_safe_str(source.get("preset")) or "").lower()
    if preset:
        filters["preset"] = preset

    return filters


def _report_feature_gate(report_key: str) -> Optional[str]:
    """
    Return an error message when a report is disabled by system settings.
    """
    if report_key == "product_search_statistics" and not _cfg_bool("SEARCH_ANALYTICS_ENABLED", True):
        return "Search analytics reporting is disabled in system settings."

    return None


def _catalog_payload() -> List[Dict[str, Any]]:
    """
    Report catalog for the admin reporting UI.
    """
    return [
        {
            "report_key": "auth_activity",
            "title": "Authentication Activity Report",
            "subtitle": "Login, logout, refresh, and failed authentication activity.",
            "supports": ["pdf", "csv"],
            "filters": ["period", "span", "days", "date_from", "date_to", "role", "event_type", "limit"],
            "kind": "standard_or_adhoc",
            "enabled": True,
        },
        {
            "report_key": "user_activity",
            "title": "User Activity Report",
            "subtitle": "System activity performed by registered users after login.",
            "supports": ["pdf", "csv"],
            "filters": ["period", "span", "days", "date_from", "date_to", "role", "action", "status", "q", "limit"],
            "kind": "standard_or_adhoc",
            "enabled": True,
        },
        {
            "report_key": "product_lifecycle",
            "title": "Product Lifecycle Report",
            "subtitle": "Product submissions, moderation actions, approvals, rejections, and related lifecycle events.",
            "supports": ["pdf", "csv"],
            "filters": ["period", "span", "days", "date_from", "date_to", "action", "actor_role", "q", "limit"],
            "kind": "standard_or_adhoc",
            "enabled": True,
        },
        {
            "report_key": "product_search_statistics",
            "title": "Product Search Statistics Report",
            "subtitle": "Search behaviour grouped by period, including top queries and user reach.",
            "supports": ["pdf", "csv"],
            "filters": ["period", "span", "days", "date_from", "date_to", "q", "limit"],
            "kind": "standard_or_adhoc",
            "enabled": _cfg_bool("SEARCH_ANALYTICS_ENABLED", True),
        },
        {
            "report_key": "moderation_sla",
            "title": "Moderation SLA Report",
            "subtitle": "Submission-to-review turnaround and SLA breach analysis.",
            "supports": ["pdf", "csv"],
            "filters": ["period", "span", "days", "date_from", "date_to", "sla_hours", "limit"],
            "kind": "standard_or_adhoc",
            "enabled": True,
        },
    ]


# ---------------------------------------------------------------------------
# Overview + Presence
# ---------------------------------------------------------------------------
@admin_reports_bp.route("/overview", methods=["GET"])
@require_access_token
@require_admin
def overview() -> Response:
    period = request.args.get("period", "week").strip().lower()
    span = _int_qp("span", 12, min_v=1, max_v=60)

    default_days = _default_report_days()
    days_raw = request.args.get("days")
    days = _int_qp("days", default_days, min_v=7, max_v=365) if days_raw not in (None, "") else default_days

    ttl = _int_qp("ttl", 300, min_v=0, max_v=3600)
    refresh = _truthy("refresh")
    demo = _truthy("demo")

    data = build_admin_overview(
        session=db.session,
        period=period,
        span=span,
        horizon_days=days,
        ttl=ttl,
        refresh=refresh,
        demo=demo,
    )

    _audit_admin_view(
        action="admin_view_reports_overview",
        target_type="report",
        metadata={
            "period": period,
            "span": span,
            "days": days,
            "ttl": ttl,
            "refresh": refresh,
            "demo": demo,
        },
    )

    return _json({"success": True, "data": data})


@admin_reports_bp.route("/presence", methods=["GET"])
@require_access_token
@require_admin
def presence() -> Response:
    limit = _int_qp("limit", 12, min_v=1, max_v=50)
    window = _int_qp("window", 10, min_v=1, max_v=180)
    ttl = _int_qp("ttl", 60, min_v=0, max_v=600)
    refresh = _truthy("refresh")

    data = build_admin_presence(
        session=db.session,
        limit=limit,
        online_minutes=window,
        ttl=ttl,
        refresh=refresh,
    )

    _audit_admin_view(
        action="admin_view_presence_report",
        target_type="report",
        metadata={
            "limit": limit,
            "window": window,
            "ttl": ttl,
            "refresh": refresh,
        },
    )

    return _json({"success": True, "data": data})


@admin_reports_bp.route("/audit-overview", methods=["GET"])
@require_access_token
@require_admin
def audit_overview() -> Response:
    period = request.args.get("period", "week").strip().lower()
    span = _int_qp("span", 12, min_v=1, max_v=60)
    days = _int_qp("days", _default_report_days(), min_v=7, max_v=365)
    ttl = _int_qp("ttl", 300, min_v=0, max_v=3600)
    refresh = _truthy("refresh")

    data = build_admin_overview(
        session=db.session,
        period=period,
        span=span,
        horizon_days=days,
        ttl=ttl,
        refresh=refresh,
        demo=False,
    )

    payload = {
        "meta": data.get("meta", {}),
        "login_stats": data.get("login_stats", {}),
        "audit_stats": data.get("audit_stats", {}),
        "recent_activity": (data.get("recent", {}) or {}).get("recent_activity", []),
    }

    _audit_admin_view(
        action="admin_view_audit_overview",
        target_type="report",
        metadata={
            "period": period,
            "span": span,
            "days": days,
            "ttl": ttl,
            "refresh": refresh,
        },
    )

    return _json({"success": True, "data": payload})


# ---------------------------------------------------------------------------
# Report catalog + standard/ad hoc generation
# ---------------------------------------------------------------------------
@admin_reports_bp.route("/catalog", methods=["GET"])
@require_access_token
@require_admin
def report_catalog() -> Response:
    reports = _catalog_payload()

    payload = {
        "supported_report_keys": list(SUPPORTED_REPORT_KEYS),
        "reports": reports,
        "defaults": {
            "default_report_days": _default_report_days(),
            "report_preview_rows": _default_preview_rows(),
            "product_review_sla_hours": _default_sla_hours(),
        },
    }

    _audit_admin_view(
        action="admin_view_report_catalog",
        target_type="report_catalog",
        metadata={"count": len(reports)},
    )

    return _json({"success": True, "data": payload})


@admin_reports_bp.route("/generate", methods=["GET", "POST"])
@require_access_token
@require_admin
def generate_report() -> Response:
    source = _request_payload()
    report_key = _normalized_report_key(source.get("report_key") or source.get("report") or "")
    if not report_key:
        return _json({"success": False, "error": "report_key is required"}, 400)

    if report_key not in SUPPORTED_REPORT_KEYS:
        return _json(
            {
                "success": False,
                "error": f"Unsupported report_key '{report_key}'",
                "supported_report_keys": list(SUPPORTED_REPORT_KEYS),
            },
            400,
        )

    gate_error = _report_feature_gate(report_key)
    if gate_error:
        return _json_error(gate_error, status=403)

    filters = _collect_report_filters(source)
    preview_default = _default_preview_rows()
    preview_limit = max(1, min(_safe_int(source.get("preview_limit"), preview_default), 200))

    try:
        built = build_report(
            session=db.session,
            report_key=report_key,
            generated_by_name=_current_admin_name(),
            generated_by_email=_current_admin_email(),
            export_format="json",
            filters=filters,
        )
    except ValueError as exc:
        return _json_error(str(exc), status=400)
    except Exception as exc:
        return _json_error(
            "Failed to generate report preview",
            status=500,
            details=_safe_str(exc) or None,
        )

    payload = {
        "report_key": report_key,
        "title": built.context.title,
        "subtitle": built.context.subtitle,
        "filename_base": built.filename_base,
        "summary": built.summary,
        "columns": built.columns,
        "row_count": len(built.rows),
        "rows_preview": built.rows[:preview_limit],
        "context": {
            "generated_at": built.context.generated_at.isoformat(),
            "generated_by_name": built.context.generated_by_name,
            "generated_by_email": built.context.generated_by_email,
            "period": built.context.period,
            "date_from": built.context.date_from.isoformat() if built.context.date_from else None,
            "date_to": built.context.date_to.isoformat() if built.context.date_to else None,
            "filters": built.context.filters,
        },
        "defaults": {
            "preview_limit": preview_default,
            "default_report_days": _default_report_days(),
            "product_review_sla_hours": _default_sla_hours(),
        },
        "available_export_formats": ["pdf", "csv"],
    }

    _audit_admin_view(
        action="admin_generate_report",
        target_type="report",
        target_id=report_key,
        metadata={
            "report_key": report_key,
            "row_count": len(built.rows),
            "preview_limit": preview_limit,
            "filters": filters,
        },
    )

    return _json({"success": True, "data": payload})


@admin_reports_bp.route("/generate/export", methods=["GET", "POST"])
@require_access_token
@require_admin
def generate_report_export() -> Response:
    source = _request_payload()
    report_key = _normalized_report_key(source.get("report_key") or source.get("report") or "")
    export_format = ((_safe_str(source.get("format")) or "pdf")).lower()

    if not report_key:
        return _json({"success": False, "error": "report_key is required"}, 400)

    if report_key not in SUPPORTED_REPORT_KEYS:
        return _json(
            {
                "success": False,
                "error": f"Unsupported report_key '{report_key}'",
                "supported_report_keys": list(SUPPORTED_REPORT_KEYS),
            },
            400,
        )

    if export_format not in {"pdf", "csv"}:
        return _json({"success": False, "error": "format must be pdf or csv"}, 400)

    gate_error = _report_feature_gate(report_key)
    if gate_error:
        return _json_error(gate_error, status=403)

    filters = _collect_report_filters(source)

    try:
        payload_bytes, mimetype, filename, built = export_report_bytes(
            session=db.session,
            report_key=report_key,
            export_format=export_format,
            generated_by_name=_current_admin_name(),
            generated_by_email=_current_admin_email(),
            filters=filters,
        )
    except ValueError as exc:
        return _json_error(str(exc), status=400)
    except Exception as exc:
        return _json_error(
            f"Failed to export {export_format.upper()} report",
            status=500,
            details=_safe_str(exc) or None,
        )

    _audit_admin_view(
        action="admin_export_report",
        target_type="report",
        target_id=report_key,
        metadata={
            "report_key": report_key,
            "format": export_format,
            "filename": filename,
            "row_count": len(built.rows),
            "filters": filters,
        },
    )

    return Response(
        payload_bytes,
        headers={
            "Content-Type": mimetype,
            "Content-Disposition": f"attachment; filename={filename}",
            "Access-Control-Expose-Headers": (
                "Content-Disposition, "
                "X-Report-Generated-At, "
                "X-Report-Generated-By, "
                "X-Report-Row-Count"
            ),
            "X-Report-Generated-At": built.context.generated_at.isoformat(),
            "X-Report-Generated-By": built.context.generated_by_name,
            "X-Report-Row-Count": str(len(built.rows)),
        },
    )


# ---------------------------------------------------------------------------
# Moderation SLA Trend (Dashboard route preserved)
# ---------------------------------------------------------------------------
@admin_reports_bp.route("/moderation-sla", methods=["GET"])
@require_access_token
@require_admin
def moderation_sla() -> Response:
    """
    SLA reporting for product moderation.

    Query params:
      period=month (supported)
      span=6
      sla_hours=48
    """
    if Product is None:
        return _json({"success": False, "error": "Product model not available"}, 500)

    period = request.args.get("period", "month").strip().lower()
    span = _int_qp("span", 6, min_v=1, max_v=24)
    sla_hours = _int_qp("sla_hours", _default_sla_hours(), min_v=1, max_v=240)

    if period != "month":
        period = "month"

    buckets = _bucket_months(span)
    start_dt = datetime.combine(buckets[0][0], datetime.min.time())
    end_dt = datetime.combine(buckets[-1][1], datetime.min.time())

    session: Session = db.session

    rows = session.execute(
        select(
            Product.product_id,
            Product.created_at,
            getattr(Product, "submitted_at", Product.created_at),
            Product.reviewed_at,
        ).where(
            Product.reviewed_at.isnot(None),
            Product.reviewed_at >= start_dt,
            Product.reviewed_at < end_dt,
        )
    ).all()

    trend: List[Dict[str, Any]] = []
    total_reviewed = 0
    total_breached = 0
    total_hours_sum = 0.0
    total_hours_count = 0

    for bucket_start, bucket_end in buckets:
        dt0 = datetime.combine(bucket_start, datetime.min.time())
        dt1 = datetime.combine(bucket_end, datetime.min.time())

        reviewed = 0
        breached = 0
        hours_sum = 0.0
        hours_count = 0

        for (_, created_at, submitted_at, reviewed_at) in rows:
            if not reviewed_at:
                continue
            if reviewed_at < dt0 or reviewed_at >= dt1:
                continue

            reviewed += 1
            hours_value = _duration_hours(submitted_at or created_at, reviewed_at)
            if hours_value is not None:
                hours_sum += hours_value
                hours_count += 1
                if hours_value > sla_hours:
                    breached += 1

        avg_hours = (hours_sum / hours_count) if hours_count else 0.0
        breach_rate = (breached / reviewed) if reviewed else 0.0

        total_reviewed += reviewed
        total_breached += breached
        total_hours_sum += hours_sum
        total_hours_count += hours_count

        trend.append(
            {
                "bucket": f"{bucket_start.year}-{bucket_start.month:02d}",
                "start": bucket_start.isoformat(),
                "end": bucket_end.isoformat(),
                "reviewed": reviewed,
                "breached": breached,
                "breach_rate": round(breach_rate, 4),
                "avg_hours": round(avg_hours, 2),
            }
        )

    summary_avg = (total_hours_sum / total_hours_count) if total_hours_count else 0.0
    summary_breach_rate = (total_breached / total_reviewed) if total_reviewed else 0.0

    payload = {
        "meta": {
            "period": "month",
            "span": span,
            "sla_hours": sla_hours,
            "generated_at": datetime.utcnow().isoformat(),
        },
        "summary": {
            "reviewed": total_reviewed,
            "breached": total_breached,
            "avg_hours": round(summary_avg, 2),
            "breach_rate": round(summary_breach_rate, 4),
        },
        "trend": trend,
    }

    _audit_admin_view(
        action="admin_view_moderation_sla_report",
        target_type="report",
        target_id="moderation_sla",
        metadata={
            "period": "month",
            "span": span,
            "sla_hours": sla_hours,
            "reviewed_total": total_reviewed,
            "breached_total": total_breached,
        },
    )

    return _json({"success": True, "data": payload})


# ---------------------------------------------------------------------------
# Legacy export route (kept for compatibility)
# ---------------------------------------------------------------------------
@admin_reports_bp.route("/export", methods=["GET"])
@require_access_token
@require_admin
def export_report_legacy() -> Response:
    """
    Backward-compatible export endpoint.

    Examples:
      /api/admin/reports/export?report=moderation_sla&format=csv
      /api/admin/reports/export?report=auth_activity&format=pdf&period=month
    """
    source = dict(request.args)
    report_key = _normalized_report_key(source.get("report") or source.get("report_key") or "")
    export_format = ((_safe_str(source.get("format")) or "csv")).lower()

    if not report_key:
        return _json({"success": False, "error": "report is required"}, 400)

    if report_key not in SUPPORTED_REPORT_KEYS:
        return _json(
            {
                "success": False,
                "error": f"Unsupported report '{report_key}'",
                "supported_report_keys": list(SUPPORTED_REPORT_KEYS),
            },
            400,
        )

    if export_format not in {"csv", "pdf"}:
        return _json({"success": False, "error": "Unsupported format"}, 400)

    gate_error = _report_feature_gate(report_key)
    if gate_error:
        return _json_error(gate_error, status=403)

    filters = _collect_report_filters(source)

    try:
        payload_bytes, mimetype, filename, built = export_report_bytes(
            session=db.session,
            report_key=report_key,
            export_format=export_format,
            generated_by_name=_current_admin_name(),
            generated_by_email=_current_admin_email(),
            filters=filters,
        )
    except ValueError as exc:
        return _json_error(str(exc), status=400)
    except Exception as exc:
        return _json_error(
            f"Failed to export {export_format.upper()} report",
            status=500,
            details=_safe_str(exc) or None,
        )

    _audit_admin_view(
        action="admin_export_report_legacy",
        target_type="report",
        target_id=report_key,
        metadata={
            "report_key": report_key,
            "format": export_format,
            "filename": filename,
            "row_count": len(built.rows),
            "filters": filters,
        },
    )

    return Response(
        payload_bytes,
        headers={
            "Content-Type": mimetype,
            "Content-Disposition": f"attachment; filename={filename}",
        },
    )