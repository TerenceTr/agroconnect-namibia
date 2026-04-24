# ============================================================================
# backend/services/audit_logger.py — Unified Audit Logging Service
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Single service layer for writing three distinct audit streams:
#
#   1. Authentication / session audit
#      -> login_events
#   2. User activity audit
#      -> user_activity_events
#   3. Admin governance audit
#      -> admin_audit_log
#
# WHY THIS FILE MATTERS:
#   A master's-level system should NOT mix:
#     • login/logout history
#     • normal user activity
#     • privileged admin actions
#
#   This service enforces that separation while still giving the codebase one
#   canonical place to write audit records.
#
# DESIGN GOALS:
#   ✅ Centralized and consistent audit writes
#   ✅ Backward-compatible helper names such as log_admin_event(...)
#   ✅ Safe by default (returns False instead of crashing the main flow)
#   ✅ Supports strict mode for callers that want failures to surface
#   ✅ Captures request context best-effort when available
#
# IMPORTANT:
#   Presence / heartbeat activity must NOT be written into login_events.
#   Use users.last_seen_at and presence-specific logic for online status.
#
# THIS VERSION FIXES:
#   ✅ Imports has_request_context from flask.ctx (Pyright-safe)
#   ✅ Does not assign plain str into AdminAuditLog.entity_id when that column
#      is typed/mapped as UUID
#   ✅ Preserves non-UUID target/entity ids in metadata for traceability
# ============================================================================
from __future__ import annotations

import logging
from typing import Any, Optional
from uuid import UUID

from flask.ctx import has_request_context
from flask.globals import request

from backend.database.db import db
from backend.models.admin_audit_event import AdminAuditLog
from backend.models.login_event import (
    AUTH_EVENT_FAILED_LOGIN,
    AUTH_EVENT_LOGIN,
    AUTH_EVENT_LOGOUT,
    AUTH_EVENT_LOGOUT_ALL,
    AUTH_EVENT_REFRESH,
    AUTH_EVENT_SESSION_EXPIRED,
    AUTH_EVENT_TOKEN_REVOKED,
    LoginEvent,
    VALID_AUTH_EVENT_TYPES,
)
from backend.models.user_activity_event import (
    ACTIVITY_STATUS_SUCCESS,
    UserActivityEvent,
)

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------------
# Role normalization
# ----------------------------------------------------------------------------
_ROLE_MAP_INT_TO_NAME: dict[int, str] = {
    1: "admin",
    2: "farmer",
    3: "customer",
}

_ROLE_MAP_STR_TO_NAME: dict[str, str] = {
    "1": "admin",
    "2": "farmer",
    "3": "customer",
    "admin": "admin",
    "administrator": "admin",
    "farmer": "farmer",
    "customer": "customer",
    "buyer": "customer",
}


# ----------------------------------------------------------------------------
# Low-level helpers
# ----------------------------------------------------------------------------
def _safe_str(value: Any) -> Optional[str]:
    """
    Convert a value to a stripped string.
    Empty strings become None.
    """
    if value is None:
        return None
    try:
        text = str(value).strip()
    except Exception:
        return None
    return text or None


def _safe_dict(value: Any) -> Optional[dict[str, Any]]:
    """
    Accept only dictionary-like payloads for JSON audit fields.
    """
    return value if isinstance(value, dict) else None


def _as_uuid(value: Any) -> Optional[UUID]:
    """
    Best-effort UUID parsing.
    """
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value).strip())
    except Exception:
        return None


def _normalize_role_name(value: Any) -> Optional[str]:
    """
    Normalize role representations to canonical names:
      admin, farmer, customer
    """
    if value is None:
        return None

    if isinstance(value, int):
        return _ROLE_MAP_INT_TO_NAME.get(value)

    raw = _safe_str(value)
    if raw is None:
        return None

    return _ROLE_MAP_STR_TO_NAME.get(raw.lower(), raw.lower())


def _merge_metadata(
    primary: Optional[dict[str, Any]],
    secondary: Optional[dict[str, Any]],
) -> Optional[dict[str, Any]]:
    """
    Merge two optional metadata dicts.

    primary wins when the same key exists in both payloads.
    """
    if primary is None and secondary is None:
        return None
    if primary is None:
        return dict(secondary or {})
    if secondary is None:
        return dict(primary)

    merged = dict(secondary)
    merged.update(primary)
    return merged


def _request_ip() -> Optional[str]:
    """
    Best-effort client IP extraction.
    """
    if not has_request_context():
        return None

    forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded_for:
        first_ip = forwarded_for.split(",")[0].strip()
        if first_ip:
            return first_ip

    return _safe_str(getattr(request, "remote_addr", None))


def _request_user_agent() -> Optional[str]:
    """
    Best-effort user-agent extraction.
    """
    if not has_request_context():
        return None
    return _safe_str(request.headers.get("User-Agent"))


def _request_route() -> Optional[str]:
    """
    Best-effort path extraction.
    """
    if not has_request_context():
        return None
    return _safe_str(getattr(request, "path", None))


def _request_method() -> Optional[str]:
    """
    Best-effort HTTP method extraction.
    """
    if not has_request_context():
        return None
    return _safe_str(getattr(request, "method", None))


def _request_id_from_headers() -> Optional[str]:
    """
    Optional request correlation ID from incoming headers.
    """
    if not has_request_context():
        return None
    return (
        _safe_str(request.headers.get("X-Request-ID"))
        or _safe_str(request.headers.get("X-Correlation-ID"))
    )


def _finalize_session(
    *,
    strict: bool = False,
    log_message: str = "Audit write failed",
) -> bool:
    """
    Commit the current DB session safely.

    IMPORTANT:
      Some request handlers may already have left the shared SQLAlchemy session
      in an aborted transaction state before audit logging runs. In that case,
      blindly calling commit() causes noisy repeated stack traces such as
      InFailedSqlTransaction.

    BEHAVIOR:
      • If the session transaction is inactive/broken, rollback first.
      • Commit if possible.
      • On failure, rollback and log gracefully.
      • In strict mode, re-raise after rollback.
    """
    try:
        try:
            tx = db.session.get_transaction()
            if tx is not None and not tx.is_active:
                db.session.rollback()
        except Exception:
            db.session.rollback()

        db.session.commit()
        return True
    except Exception as exc:
        db.session.rollback()

        message = str(exc)
        if "InFailedSqlTransaction" in message or "current transaction is aborted" in message:
            logger.warning(
                "%s (skipped because request session was already aborted)",
                log_message,
            )
        else:
            logger.exception(log_message)

        if strict:
            raise
        return False


# ----------------------------------------------------------------------------
# Authentication / session audit
# ----------------------------------------------------------------------------
def log_auth_event(
    *,
    user_id: Any,
    event_type: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Write an authentication/session event to login_events.

    VALID USES:
      - login
      - logout
      - logout_all
      - refresh
      - failed_login
      - session_expired
      - token_revoked

    IMPORTANT:
      Do not use this for general activity or "seen" heartbeats.

    Returns:
      True  -> written successfully
      False -> skipped/failed safely
    """
    user_uuid = _as_uuid(user_id)
    event_name = _safe_str(event_type)

    if user_uuid is None or not event_name:
        return False

    if event_name not in VALID_AUTH_EVENT_TYPES:
        logger.warning("Skipped unsupported auth event_type=%r", event_name)
        return False

    try:
        entry = LoginEvent()
        entry.user_id = user_uuid
        entry.event_type = event_name
        entry.ip_address = _safe_str(ip_address) or _request_ip()
        entry.user_agent = _safe_str(user_agent) or _request_user_agent()

        db.session.add(entry)
        if not commit:
            return True
        return _finalize_session(
            strict=strict,
            log_message=f"Failed to write auth event '{event_name}'",
        )
    except Exception:
        db.session.rollback()
        logger.exception("Failed to prepare auth event '%s'", event_name)
        if strict:
            raise
        return False


def log_login(
    *,
    user_id: Any,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Convenience helper for successful login events.
    """
    return log_auth_event(
        user_id=user_id,
        event_type=AUTH_EVENT_LOGIN,
        ip_address=ip_address,
        user_agent=user_agent,
        strict=strict,
        commit=commit,
    )


def log_logout(
    *,
    user_id: Any,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Convenience helper for explicit logout events.
    """
    return log_auth_event(
        user_id=user_id,
        event_type=AUTH_EVENT_LOGOUT,
        ip_address=ip_address,
        user_agent=user_agent,
        strict=strict,
        commit=commit,
    )


def log_logout_all(
    *,
    user_id: Any,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Convenience helper for logout-all / revoke-all-sessions events.
    """
    return log_auth_event(
        user_id=user_id,
        event_type=AUTH_EVENT_LOGOUT_ALL,
        ip_address=ip_address,
        user_agent=user_agent,
        strict=strict,
        commit=commit,
    )


def log_failed_login(
    *,
    user_id: Any,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Convenience helper for failed login attempts where the user_id is known.

    NOTE:
      The current schema requires user_id, so unknown-email/unknown-phone
      failures cannot be written here without a separate security log table.
    """
    return log_auth_event(
        user_id=user_id,
        event_type=AUTH_EVENT_FAILED_LOGIN,
        ip_address=ip_address,
        user_agent=user_agent,
        strict=strict,
        commit=commit,
    )


def log_session_refresh(
    *,
    user_id: Any,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Convenience helper for refresh-token/session-refresh activity.
    """
    return log_auth_event(
        user_id=user_id,
        event_type=AUTH_EVENT_REFRESH,
        ip_address=ip_address,
        user_agent=user_agent,
        strict=strict,
        commit=commit,
    )


def log_session_expired(
    *,
    user_id: Any,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Convenience helper for session-expiry events.
    """
    return log_auth_event(
        user_id=user_id,
        event_type=AUTH_EVENT_SESSION_EXPIRED,
        ip_address=ip_address,
        user_agent=user_agent,
        strict=strict,
        commit=commit,
    )


def log_token_revoked(
    *,
    user_id: Any,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Convenience helper for token revocation events.
    """
    return log_auth_event(
        user_id=user_id,
        event_type=AUTH_EVENT_TOKEN_REVOKED,
        ip_address=ip_address,
        user_agent=user_agent,
        strict=strict,
        commit=commit,
    )


# ----------------------------------------------------------------------------
# User activity audit
# ----------------------------------------------------------------------------
def log_user_activity(
    *,
    user_id: Any,
    action: str,
    role_name: Optional[Any] = None,
    session_id: Optional[str] = None,
    request_id: Optional[str] = None,
    target_type: Optional[str] = None,
    target_id: Optional[Any] = None,
    entity_type: Optional[str] = None,   # alias
    entity_id: Optional[Any] = None,     # alias
    route: Optional[str] = None,
    http_method: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    status: str = ACTIVITY_STATUS_SUCCESS,
    error_message: Optional[str] = None,
    metadata_json: Optional[dict[str, Any]] = None,
    metadata: Optional[dict[str, Any]] = None,  # alias
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Write a non-auth user activity event.

    Examples:
      action="view_product"
      action="add_to_cart"
      action="place_order"
      action="product_created"
      action="delivery_fee_set"
      action="payment_proof_uploaded"

    Returns:
      True  -> written successfully
      False -> skipped/failed safely
    """
    user_uuid = _as_uuid(user_id)
    action_name = _safe_str(action)
    status_name = _safe_str(status) or ACTIVITY_STATUS_SUCCESS

    if user_uuid is None or not action_name:
        return False

    resolved_target_type = _safe_str(target_type) or _safe_str(entity_type)
    resolved_target_id = _as_uuid(target_id) or _as_uuid(entity_id)
    resolved_metadata = _merge_metadata(_safe_dict(metadata_json), _safe_dict(metadata))

    try:
        entry = UserActivityEvent()
        entry.user_id = user_uuid
        entry.session_id = _safe_str(session_id)
        entry.request_id = _safe_str(request_id) or _request_id_from_headers()
        entry.role_name = _normalize_role_name(role_name)
        entry.action = action_name
        entry.target_type = resolved_target_type
        entry.target_id = resolved_target_id
        entry.route = _safe_str(route) or _request_route()
        entry.http_method = _safe_str(http_method) or _request_method()
        entry.ip_address = _safe_str(ip_address) or _request_ip()
        entry.user_agent = _safe_str(user_agent) or _request_user_agent()
        entry.status = status_name
        entry.error_message = _safe_str(error_message)
        entry.metadata_json = resolved_metadata

        db.session.add(entry)
        if not commit:
            return True
        return _finalize_session(
            strict=strict,
            log_message=f"Failed to write user activity '{action_name}'",
        )
    except Exception:
        db.session.rollback()
        logger.exception("Failed to prepare user activity '%s'", action_name)
        if strict:
            raise
        return False


# ----------------------------------------------------------------------------
# Admin governance audit
# ----------------------------------------------------------------------------
def log_admin_event(
    *,
    admin_id: Any,
    action: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[Any] = None,
    target_type: Optional[str] = None,   # legacy alias
    target_id: Optional[Any] = None,     # legacy alias
    metadata: Optional[dict[str, Any]] = None,
    metadata_json: Optional[dict[str, Any]] = None,  # alias
    strict: bool = False,
    commit: bool = True,
) -> bool:
    """
    Write a privileged governance/admin audit event.

    Examples:
      action="approve_product"
      action="reject_product"
      action="change_user_role"
      action="delete_user"
      action="update_settings"

    Backward compatibility:
      Supports both entity_type/entity_id and target_type/target_id.

    IMPORTANT:
      AdminAuditLog.entity_id is treated as UUID-compatible in typed ORM code.
      If callers pass a non-UUID id (for example a slug or text key), we do NOT
      force it into the UUID column. Instead we preserve the raw value in
      metadata under `raw_entity_id` / `raw_target_id`.
    """
    admin_uuid = _as_uuid(admin_id)
    action_name = _safe_str(action)

    if admin_uuid is None or not action_name:
        return False

    resolved_entity_type = _safe_str(entity_type) or _safe_str(target_type)

    # Typed UUID-safe assignment for the model column.
    resolved_entity_uuid = _as_uuid(entity_id) or _as_uuid(target_id)

    # Preserve raw non-UUID identifiers in metadata so audit evidence is not lost.
    raw_entity_id = _safe_str(entity_id)
    raw_target_id = _safe_str(target_id)

    extra_metadata: dict[str, Any] = {}
    if raw_entity_id and resolved_entity_uuid is None:
        extra_metadata["raw_entity_id"] = raw_entity_id
    if raw_target_id and resolved_entity_uuid is None and raw_target_id != raw_entity_id:
        extra_metadata["raw_target_id"] = raw_target_id
    if resolved_entity_type:
        extra_metadata["resolved_entity_type"] = resolved_entity_type

    resolved_metadata = _merge_metadata(
        _safe_dict(metadata_json),
        _merge_metadata(_safe_dict(metadata), extra_metadata or None),
    )

    try:
        entry = AdminAuditLog()
        entry.admin_id = admin_uuid
        entry.action = action_name
        entry.entity_type = resolved_entity_type
        entry.entity_id = resolved_entity_uuid
        entry.metadata_json = resolved_metadata

        db.session.add(entry)
        if not commit:
            return True
        return _finalize_session(
            strict=strict,
            log_message=f"Failed to write admin audit '{action_name}'",
        )
    except Exception:
        db.session.rollback()
        logger.exception("Failed to prepare admin audit '%s'", action_name)
        if strict:
            raise
        return False


# ----------------------------------------------------------------------------
# Optional class wrapper for cleaner imports in routes/services
# ----------------------------------------------------------------------------
class AuditLogger:
    """
    Thin class wrapper around module-level functions.

    This gives route code a readable style such as:
      AuditLogger.log_login(...)
      AuditLogger.log_user_activity(...)
      AuditLogger.log_admin_event(...)
    """

    @staticmethod
    def log_login(**kwargs: Any) -> bool:
        return log_login(**kwargs)

    @staticmethod
    def log_logout(**kwargs: Any) -> bool:
        return log_logout(**kwargs)

    @staticmethod
    def log_logout_all(**kwargs: Any) -> bool:
        return log_logout_all(**kwargs)

    @staticmethod
    def log_failed_login(**kwargs: Any) -> bool:
        return log_failed_login(**kwargs)

    @staticmethod
    def log_session_refresh(**kwargs: Any) -> bool:
        return log_session_refresh(**kwargs)

    @staticmethod
    def log_session_expired(**kwargs: Any) -> bool:
        return log_session_expired(**kwargs)

    @staticmethod
    def log_token_revoked(**kwargs: Any) -> bool:
        return log_token_revoked(**kwargs)

    @staticmethod
    def log_auth_event(**kwargs: Any) -> bool:
        return log_auth_event(**kwargs)

    @staticmethod
    def log_user_activity(**kwargs: Any) -> bool:
        return log_user_activity(**kwargs)

    @staticmethod
    def log_admin_event(**kwargs: Any) -> bool:
        return log_admin_event(**kwargs)