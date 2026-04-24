# ============================================================================
# backend/routes/admin_settings.py — Admin System Settings (JWT)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin-facing API for reading, updating, and projecting system settings.
#
# WHAT THIS VERSION DOES:
#   • Uses backend.services.system_settings as the single source of truth
#   • Keeps older admin route shapes working:
#       GET  /api/admin/settings
#       POST /api/admin/settings
#       POST /api/admin/cache/flush
#   • Adds a public-safe route for frontend runtime policy:
#       GET  /api/admin/settings/public
#   • Applies updated settings back into current_app.config immediately
#   • Records admin activity and governance audit trails
#
# HARDENING IN THIS VERSION:
#   ✅ Removes all uses of current_app._get_current_object()
#   ✅ Uses a typed helper that returns the active Flask app via cast()
#   ✅ Accepts BOTH payload shapes for save:
#        - raw settings object
#        - { settings: { ... } }
#   ✅ Wraps GET / POST / public / flush routes with safe error handling
#      so the frontend gets a meaningful message instead of a generic
#      "Failed to save settings"
#   ✅ Logs failures server-side for easier diagnosis
#
# WHY THIS HELPS YOUR CURRENT ISSUE:
#   The frontend currently shows a generic toast when POST /api/admin/settings
#   fails. This version returns an explicit JSON error response and keeps the
#   route contract stable for the existing AdminSettingsPage.
# ============================================================================

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional, cast

from flask.app import Flask
from flask.blueprints import Blueprint
from flask.globals import current_app, g, request
from flask.json import jsonify
from flask.wrappers import Response

from backend.models.user import ROLE_ADMIN, User
from backend.services.audit_logger import AuditLogger
from backend.services.system_settings import (
    apply_system_settings_to_app,
    deep_merge,
    normalize_settings,
    public_settings_projection,
    read_system_settings,
    write_system_settings,
)
from backend.utils.require_auth import require_access_token

admin_settings_bp = Blueprint("admin_settings", __name__)
logger = logging.getLogger("agroconnect.admin_settings")


# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------
def _json(payload: Any, status: int = 200) -> Response:
    """Small helper to return a Flask JSON response with an explicit status."""
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _safe_str(value: Any, fallback: str = "") -> str:
    """Best-effort string conversion that never raises."""
    if value is None:
        return fallback
    try:
        text = str(value).strip()
        return text if text else fallback
    except Exception:
        return fallback


def _as_dict(value: Any) -> dict[str, Any]:
    """Force a dict shape for incoming JSON fragments."""
    return value if isinstance(value, dict) else {}


def _extract_settings_payload(body: Any) -> dict[str, Any]:
    """
    Support both save payload styles:
      • POST { ...full settings object... }
      • POST { "settings": { ...full settings object... } }
    """
    body_dict = _as_dict(body)
    nested = body_dict.get("settings")
    if isinstance(nested, dict):
        return nested
    return body_dict


def _active_app() -> Flask:
    """
    Return the active Flask app as a typed Flask instance.
    """
    return cast(Flask, current_app)


# ----------------------------------------------------------------------------
# Current-user helpers
# ----------------------------------------------------------------------------
def _current_user() -> Optional[User]:
    """
    Read the authenticated user from common request locations.
    """
    user = getattr(g, "current_user", None)
    if isinstance(user, User):
        return user

    user2 = getattr(request, "current_user", None)
    if isinstance(user2, User):
        return user2

    return None


def _admin_guard() -> Optional[Response]:
    """
    Enforce that the current request is authenticated as an admin.
    """
    user = _current_user()
    if user is None:
        return _json({"success": False, "message": "Authentication required"}, 401)

    if getattr(user, "role", None) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)

    return None


def _current_admin_uuid() -> Optional[uuid.UUID]:
    """
    Convert the current admin's id into a UUID if possible.
    """
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
    """
    Derive a role label for audit logging.
    """
    user = _current_user()
    if user is None:
        return "admin"

    role_name = getattr(user, "role_name", None)
    if isinstance(role_name, str) and role_name.strip():
        return role_name.strip().lower()

    role_raw = getattr(user, "role", None)
    try:
        role_int = int(role_raw) if role_raw is not None else ROLE_ADMIN
    except Exception:
        role_int = ROLE_ADMIN

    return {1: "admin", 2: "farmer", 3: "customer"}.get(role_int, "admin")


# ----------------------------------------------------------------------------
# Request metadata helpers for audit trails
# ----------------------------------------------------------------------------
def _request_session_id() -> Optional[str]:
    """
    Try to extract a client/session id from headers or request JSON.
    """
    header_value = (
        request.headers.get("X-Session-ID")
        or request.headers.get("X-Client-Session")
        or request.headers.get("X-Device-Session")
    )
    if header_value:
        return _safe_str(header_value)[:128] or None

    body = request.get_json(silent=True) or {}
    if isinstance(body, dict):
        raw = body.get("sessionId") or body.get("session_id")
        if raw is not None:
            return _safe_str(raw)[:128] or None

    return None


def _client_ip() -> Optional[str]:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return _safe_str(xff.split(",")[0])[:64] or None
    return request.remote_addr or None


def _user_agent() -> Optional[str]:
    ua = request.headers.get("User-Agent")
    return ua[:256] if ua else None


# ----------------------------------------------------------------------------
# Audit wrappers
# ----------------------------------------------------------------------------
def _audit_admin_view(
    *,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[Any] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """Record a user-activity style audit entry for admin endpoint usage."""
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


def _audit_admin_governance(
    *,
    action: str,
    entity_type: str,
    entity_id: Any,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """Record a governance/admin-audit style entry for privileged mutations."""
    admin_uuid = _current_admin_uuid()
    if admin_uuid is None:
        return

    try:
        AuditLogger.log_admin_event(
            admin_id=admin_uuid,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            metadata_json=metadata or {},
        )
    except TypeError:
        try:
            AuditLogger.log_admin_event(
                admin_id=admin_uuid,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                metadata=metadata or {},
            )
        except Exception:
            pass
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Diff helper
# ----------------------------------------------------------------------------
def _collect_changed_fields(
    before: dict[str, Any],
    after: dict[str, Any],
    prefix: str = "",
) -> list[str]:
    """
    Recursively collect dotted paths that changed between two dictionaries.
    """
    changed: list[str] = []
    keys = sorted(set(before.keys()) | set(after.keys()))

    for key in keys:
        full_key = f"{prefix}.{key}" if prefix else key
        before_value = before.get(key)
        after_value = after.get(key)

        if isinstance(before_value, dict) and isinstance(after_value, dict):
            changed.extend(_collect_changed_fields(before_value, after_value, full_key))
        elif before_value != after_value:
            changed.append(full_key)

    return changed


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@admin_settings_bp.route("/settings", methods=["GET"])
@require_access_token
def get_settings() -> Response:
    """
    Return the full admin settings payload.
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    try:
        app = _active_app()
        settings = read_system_settings(app=app)
        apply_system_settings_to_app(app, settings)

        _audit_admin_view(
            action="admin_view_settings",
            target_type="system_settings",
            metadata={
                "cache_ttl": int(settings.get("cache_ttl", 300)),
                "maintenance": bool(settings.get("maintenance", False)),
                "default_report_days": int(_as_dict(settings.get("platform")).get("default_report_days", 90)),
                "low_stock_threshold": int(_as_dict(settings.get("marketplace")).get("low_stock_threshold", 5)),
                "review_sla_hours": int(_as_dict(settings.get("moderation")).get("product_review_sla_hours", 48)),
            },
        )
        return _json(settings, 200)
    except Exception as exc:
        logger.exception("Failed to load admin settings")
        return _json(
            {
                "success": False,
                "message": "Could not load system settings.",
                "details": _safe_str(exc, "Unknown error"),
            },
            500,
        )


@admin_settings_bp.route("/settings/public", methods=["GET"])
def get_public_settings() -> Response:
    """
    Return only safe runtime settings for public/frontend consumption.
    """
    try:
        app = _active_app()
        settings = read_system_settings(app=app)
        apply_system_settings_to_app(app, settings)
        public_payload = public_settings_projection(settings)
        return _json({"success": True, "data": public_payload}, 200)
    except Exception as exc:
        logger.exception("Failed to load public settings")
        return _json(
            {
                "success": False,
                "message": "Could not load public system settings.",
                "details": _safe_str(exc, "Unknown error"),
            },
            500,
        )


@admin_settings_bp.route("/settings", methods=["POST"])
@require_access_token
def save_settings() -> Response:
    """
    Persist admin settings and immediately apply them to current_app.config.

    This route supports partial updates:
      • omitted sections keep their previous values
      • incoming values are normalized through system_settings.normalize_settings
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    try:
        app = _active_app()
        body = request.get_json(silent=True) or {}
        body_dict = _extract_settings_payload(body)

        before = read_system_settings(app=app)
        merged_candidate = deep_merge(before, body_dict)
        after = normalize_settings(merged_candidate, app=app)
        changed_fields = _collect_changed_fields(before, after)

        write_system_settings(after, app=app)
        apply_system_settings_to_app(app, after)

        _audit_admin_governance(
            action="update_system_settings",
            entity_type="system_settings",
            entity_id="admin_settings",
            metadata={
                "before": before,
                "after": after,
                "changed_fields": changed_fields,
            },
        )

        _audit_admin_view(
            action="admin_update_settings",
            target_type="system_settings",
            metadata={
                "changed_fields": changed_fields,
                "cache_ttl": int(after.get("cache_ttl", 300)),
                "maintenance": bool(after.get("maintenance", False)),
            },
        )

        return _json(
            {
                "success": True,
                "message": "System settings updated successfully.",
                "changed_fields": changed_fields,
                "settings": after,
                "cache_ttl": int(after.get("cache_ttl", 300)),
                "maintenance": bool(after.get("maintenance", False)),
                "version": _safe_str(after.get("version"), "-"),
            },
            200,
        )
    except Exception as exc:
        logger.exception("Failed to save admin settings")
        return _json(
            {
                "success": False,
                "message": "Could not save system settings.",
                "details": _safe_str(exc, "Unknown error"),
            },
            500,
        )


@admin_settings_bp.route("/cache/flush", methods=["POST"])
@require_access_token
def flush_cache() -> Response:
    """
    Flush application cache.

    In the current development setup this remains a no-op, but the route and
    audit behavior are preserved so a real cache backend can be added later
    without changing the admin UI contract.
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    try:
        app = _active_app()
        settings = read_system_settings(app=app)

        _audit_admin_view(
            action="admin_flush_cache",
            target_type="cache",
            metadata={
                "mode": "no_op_dev",
                "cache_ttl": int(settings.get("cache_ttl", 300)),
                "report_preview_rows": int(_as_dict(settings.get("platform")).get("report_preview_rows", 25)),
            },
        )

        _audit_admin_governance(
            action="flush_cache",
            entity_type="system_cache",
            entity_id="application_cache",
            metadata={
                "mode": "no_op_dev",
                "triggered_from": "admin_settings",
            },
        )

        return _json({"success": True, "message": "Cache flushed (no-op in dev)."}, 200)
    except Exception as exc:
        logger.exception("Failed to flush admin cache")
        return _json(
            {
                "success": False,
                "message": "Could not flush cache.",
                "details": _safe_str(exc, "Unknown error"),
            },
            500,
        )
