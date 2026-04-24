# ============================================================================
# backend/routes/admin_notifications.py — Admin Messaging & Broadcast Control
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Professional admin communication endpoints for:
#     • single-recipient messages
#     • audience broadcasts
#     • recipient directory search
#     • audience coverage summaries
#
# DESIGN GOALS:
#   ✅ Admin can send to one intended recipient OR a broadcast audience
#   ✅ Supports SMS, Email, or both channels together
#   ✅ Persists in-app announcements for traceability
#   ✅ Logs SMS delivery attempts into sms_logs (DB-dump aligned)
#   ✅ Uses SMTP-aware email sending with explicit fallback reporting
#   ✅ Writes governance audit evidence for administrative accountability
#
# SETTINGS INTEGRATION:
#   ✅ Respects IN_APP_NOTIFICATIONS_ENABLED
#   ✅ Respects EMAIL_NOTIFICATIONS_ENABLED / SMS_NOTIFICATIONS_ENABLED
#   ✅ Respects BROADCAST_EMAIL_ENABLED / BROADCAST_SMS_ENABLED for broadcasts
#
# IMPORTANT:
#   • Admin in-app messages are stored as admin_announcement, not order-like
#     notifications.
#   • Email delivery uses send_email_result(...) so the route can tell the
#     difference between real SMTP delivery and console/dev fallback.
# ============================================================================
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Optional

from flask.blueprints import Blueprint
from flask.globals import current_app, g, request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import or_, select, text

from backend.database.db import db
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User
from backend.services.audit_logger import AuditLogger
from backend.services.mailer import send_email_result
from backend.services.notifications import notify_user
from backend.services.sms_service import send_sms
from backend.utils.require_auth import require_access_token

admin_notifications_bp = Blueprint("admin_notifications", __name__)


# ----------------------------------------------------------------------------
# Basic helpers
# ----------------------------------------------------------------------------
def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _safe_str(value: Any, fallback: str = "") -> str:
    if isinstance(value, str):
        return value.strip()
    if value is None:
        return fallback
    try:
        return str(value).strip()
    except Exception:
        return fallback


def _cfg_bool(name: str, default: bool) -> bool:
    value = current_app.config.get(name, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _as_uuid(value: Any) -> Optional[uuid.UUID]:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(_safe_str(value))
    except Exception:
        return None


def _current_user() -> Optional[User]:
    user = getattr(g, "current_user", None)
    return user if isinstance(user, User) else None


def _admin_guard() -> Optional[Response]:
    user = _current_user()
    if user is None:
        return _json({"success": False, "message": "Authentication required"}, 401)
    if getattr(user, "role", None) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)
    return None


# ----------------------------------------------------------------------------
# Audit helpers
# ----------------------------------------------------------------------------
def _request_session_id() -> Optional[str]:
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
        return xff.split(",")[0].strip()[:64] or None
    return request.remote_addr or None


def _user_agent() -> Optional[str]:
    ua = request.headers.get("User-Agent")
    return ua[:256] if ua else None


def _current_admin_uuid() -> Optional[uuid.UUID]:
    user = _current_user()
    if user is None:
        return None

    raw = getattr(user, "id", None) or getattr(user, "user_id", None)
    return _as_uuid(raw)


def _current_admin_role_name() -> str:
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


def _audit_admin_view(
    *,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[Any] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
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
# Role / audience helpers
# ----------------------------------------------------------------------------
def _role_label(role_value: Any) -> str:
    try:
        role_int = int(role_value)
    except Exception:
        role_int = 0

    if role_int == ROLE_ADMIN:
        return "admin"
    if role_int == ROLE_FARMER:
        return "farmer"
    if role_int == ROLE_CUSTOMER:
        return "customer"
    return "user"


def _normalize_role_filter(raw: Any) -> str:
    role = _safe_str(raw, "all").lower()

    if role in {"farmer", "farmers"}:
        return "farmers"
    if role in {"customer", "customers"}:
        return "customers"
    if role in {"admin", "admins", "administrator", "administrators"}:
        return "admins"
    return "all"


def _audience_label(role_filter: str) -> str:
    if role_filter == "farmers":
        return "Farmers"
    if role_filter == "customers":
        return "Customers"
    if role_filter == "admins":
        return "Administrators"
    return "All Users"


def _base_user_query() -> Any:
    query = select(User).where(User.is_active.is_(True))  # type: ignore[attr-defined]
    query = query.where(User.deleted_at.is_(None))  # type: ignore[attr-defined]
    return query


def _apply_role_filter(query: Any, role_filter: str) -> Any:
    if role_filter == "farmers":
        return query.where(User.role == ROLE_FARMER)
    if role_filter == "customers":
        return query.where(User.role == ROLE_CUSTOMER)
    if role_filter == "admins":
        return query.where(User.role == ROLE_ADMIN)
    return query


def _user_has_phone(user: User) -> bool:
    return bool(_safe_str(getattr(user, "phone", None)))


def _user_has_email(user: User) -> bool:
    return bool(_safe_str(getattr(user, "email", None)))


def _serialize_recipient(user: User) -> dict[str, Any]:
    full_name = _safe_str(getattr(user, "full_name", None), "User")
    phone = _safe_str(getattr(user, "phone", None))
    email = _safe_str(getattr(user, "email", None))
    role_name = _role_label(getattr(user, "role", None))

    return {
        "id": str(getattr(user, "id")),
        "full_name": full_name,
        "phone": phone,
        "email": email,
        "role": role_name,
        "role_name": role_name,
        "location": _safe_str(getattr(user, "location", None)),
        "has_sms": bool(phone),
        "has_email": bool(email),
    }


def _resolve_recipients(*, mode: str, audience: dict[str, Any]) -> tuple[list[User], str, Optional[str]]:
    """
    Resolve recipients for the requested dispatch mode.

    Returns:
      (users, normalized_role_filter, error_message)
    """
    normalized_mode = "single" if _safe_str(mode).lower() == "single" else "broadcast"
    role_filter = _normalize_role_filter(audience.get("role"))

    if normalized_mode == "single":
        target_id = _as_uuid(audience.get("user_id"))
        if target_id is None:
            return [], role_filter, "Select a recipient before sending"

        user = db.session.execute(
            _base_user_query().where(User.id == target_id)
        ).scalars().first()

        if user is None:
            return [], role_filter, "Selected recipient could not be found"

        return [user], role_filter, None

    query = _apply_role_filter(_base_user_query(), role_filter)
    current_admin = _current_user()
    current_admin_id = getattr(current_admin, "id", None) if current_admin is not None else None
    if current_admin_id is not None:
        query = query.where(User.id != current_admin_id)

    users = db.session.execute(
        query.order_by(User.full_name.asc(), User.email.asc())
    ).scalars().all()
    return users, role_filter, None


def _role_announcements_path(user: User) -> str:
    role_name = _role_label(getattr(user, "role", None))
    if role_name == "farmer":
        return "/dashboard/farmer/announcements"
    if role_name == "customer":
        return "/dashboard/customer/announcements"
    if role_name == "admin":
        return "/dashboard/admin/messaging"
    return "/dashboard"


# ----------------------------------------------------------------------------
# Channel / settings policy helpers
# ----------------------------------------------------------------------------
def _channel_allowed(channel: str, mode: str) -> bool:
    """
    Enforce communication policy from shared settings.

    Direct messages use the general email/sms toggles.
    Broadcasts additionally require broadcast-specific toggles.
    """
    normalized_channel = _safe_str(channel).lower()
    normalized_mode = "single" if _safe_str(mode).lower() == "single" else "broadcast"

    if normalized_channel == "email":
        if not _cfg_bool("EMAIL_NOTIFICATIONS_ENABLED", True):
            return False
        if normalized_mode == "broadcast" and not _cfg_bool("BROADCAST_EMAIL_ENABLED", True):
            return False
        return True

    if normalized_channel == "sms":
        if not _cfg_bool("SMS_NOTIFICATIONS_ENABLED", True):
            return False
        if normalized_mode == "broadcast" and not _cfg_bool("BROADCAST_SMS_ENABLED", True):
            return False
        return True

    return False


def _validate_channels(channels: list[str], mode: str) -> Optional[str]:
    """
    Validate selected delivery channels against runtime policy.
    """
    if not channels:
        return "Select at least one delivery channel"

    disallowed = [c for c in channels if not _channel_allowed(c, mode)]
    if not disallowed:
        return None

    if len(disallowed) == 1:
        channel = disallowed[0]
        if mode == "broadcast":
            if channel == "email":
                return "Broadcast email is disabled in system settings."
            if channel == "sms":
                return "Broadcast SMS is disabled in system settings."
        else:
            if channel == "email":
                return "Email notifications are disabled in system settings."
            if channel == "sms":
                return "SMS notifications are disabled in system settings."

    return "One or more selected channels are disabled in system settings."


# ----------------------------------------------------------------------------
# Delivery / notification helpers
# ----------------------------------------------------------------------------
def _fallback_subject(subject: str, message: str) -> str:
    clean_subject = _safe_str(subject)
    if clean_subject:
        return clean_subject

    clean_message = " ".join(_safe_str(message).split())
    if clean_message:
        shortened = clean_message[:72].rstrip()
        return f"AgroConnect Notice — {shortened}"

    return "AgroConnect Notice"


def _dispatch_title(subject: str, mode: str, role_filter: str) -> str:
    clean_subject = _safe_str(subject)
    if clean_subject:
        return clean_subject[:180]

    if mode == "single":
        return "Direct administrative announcement"

    if role_filter == "farmers":
        return "Administrative announcement to farmers"
    if role_filter == "customers":
        return "Administrative announcement to customers"
    if role_filter == "admins":
        return "Administrative announcement to administrators"
    return "Administrative platform announcement"


def _build_announcement_payload(
    *,
    recipient: User,
    dispatch_id: str,
    mode: str,
    role_filter: str,
    channels: list[str],
    subject: str,
) -> dict[str, Any]:
    return {
        "dispatch_id": dispatch_id,
        "origin": "admin_messaging",
        "category": "announcements",
        "mode": mode,
        "audience_role": role_filter,
        "channels": channels,
        "subject": subject,
        "recipient_role": _role_label(getattr(recipient, "role", None)),
        "action_url": _role_announcements_path(recipient),
        "action_label": "Open announcements",
        "show_total": False,
        "announcement_priority": "normal",
    }


def _build_email_html(*, heading: str, message: str) -> str:
    escaped_heading = heading.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    escaped_message = (
        message.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", "<br>")
    )

    return f"""
<!doctype html>
<html>
  <body style="margin:0;padding:0;background:#f6fbf7;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
    <div style="max-width:680px;margin:0 auto;padding:24px;">
      <div style="background:#ffffff;border:1px solid #d8f3dc;border-radius:18px;overflow:hidden;">
        <div style="padding:18px 22px;background:#eaf7f0;border-bottom:1px solid #d8f3dc;">
          <div style="font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#40916c;">
            AgroConnect Namibia
          </div>
          <div style="margin-top:6px;font-size:22px;font-weight:800;color:#1b4332;">
            {escaped_heading}
          </div>
        </div>
        <div style="padding:22px;font-size:15px;line-height:1.7;color:#334155;">
          {escaped_message}
        </div>
      </div>
      <div style="padding:12px 4px 0 4px;font-size:12px;color:#64748b;">
        This message was sent from the AgroConnect Namibia administrative communications workspace.
      </div>
    </div>
  </body>
</html>
""".strip()


def _insert_sms_log(
    *,
    user_id: uuid.UUID,
    message: str,
    context: dict[str, Any],
    status: str,
    error_text: str = "",
    sent: bool = False,
) -> None:
    """
    Insert directly into sms_logs.

    Raw SQL is used deliberately because the current ORM model for sms_logs may
    not perfectly mirror the latest DB dump structure.
    """
    now = datetime.utcnow()
    db.session.execute(
        text(
            "INSERT INTO public.sms_logs "
            "(user_id, message_content, timestamp, status, template_name, context, provider, attempt_count, last_error, queued_at, sent_at) "
            "VALUES (:user_id, :message_content, :timestamp, :status, :template_name, CAST(:context AS jsonb), :provider, :attempt_count, :last_error, :queued_at, :sent_at)"
        ),
        {
            "user_id": str(user_id),
            "message_content": message,
            "timestamp": now,
            "status": status,
            "template_name": "admin_messaging_dispatch",
            "context": json.dumps(context),
            "provider": "internal",
            "attempt_count": 1,
            "last_error": error_text or None,
            "queued_at": now,
            "sent_at": now if sent else None,
        },
    )


# ----------------------------------------------------------------------------
# Read endpoints for the professional admin UI
# ----------------------------------------------------------------------------
@admin_notifications_bp.route("/audience-summary", methods=["GET"])
@require_access_token
def audience_summary() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    users = db.session.execute(_base_user_query()).scalars().all()

    summary: dict[str, dict[str, Any]] = {
        "all": {"label": "All Users", "total": 0, "sms_reachable": 0, "email_reachable": 0},
        "farmers": {"label": "Farmers", "total": 0, "sms_reachable": 0, "email_reachable": 0},
        "customers": {"label": "Customers", "total": 0, "sms_reachable": 0, "email_reachable": 0},
        "admins": {"label": "Administrators", "total": 0, "sms_reachable": 0, "email_reachable": 0},
    }

    for user in users:
        summary["all"]["total"] += 1
        summary["all"]["sms_reachable"] += 1 if _user_has_phone(user) else 0
        summary["all"]["email_reachable"] += 1 if _user_has_email(user) else 0

        role_name = _role_label(getattr(user, "role", None))
        if role_name == "farmer":
            bucket = "farmers"
        elif role_name == "customer":
            bucket = "customers"
        elif role_name == "admin":
            bucket = "admins"
        else:
            continue

        summary[bucket]["total"] += 1
        summary[bucket]["sms_reachable"] += 1 if _user_has_phone(user) else 0
        summary[bucket]["email_reachable"] += 1 if _user_has_email(user) else 0

    _audit_admin_view(
        action="admin_view_notification_audience_summary",
        target_type="communication_audience",
        metadata={"total_users": summary["all"]["total"]},
    )

    return _json({"success": True, "data": summary})


@admin_notifications_bp.route("/recipients", methods=["GET"])
@require_access_token
def recipients() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    q_raw = _safe_str(request.args.get("q"))
    role_filter = _normalize_role_filter(request.args.get("role"))

    try:
        limit = int(request.args.get("limit", 8))
    except Exception:
        limit = 8
    limit = max(1, min(limit, 25))

    query = _apply_role_filter(_base_user_query(), role_filter)

    if q_raw:
        like = f"%{q_raw}%"
        query = query.where(
            or_(
                User.full_name.ilike(like),  # type: ignore[attr-defined]
                User.email.ilike(like),      # type: ignore[attr-defined]
                User.phone.ilike(like),      # type: ignore[attr-defined]
            )
        )

    rows = db.session.execute(
        query.order_by(User.full_name.asc(), User.email.asc()).limit(limit)
    ).scalars().all()

    _audit_admin_view(
        action="admin_search_notification_recipients",
        target_type="communication_recipient_directory",
        metadata={
            "q": q_raw,
            "role": role_filter,
            "count": len(rows),
            "limit": limit,
        },
    )

    return _json(
        {
            "success": True,
            "data": {
                "q": q_raw,
                "role": role_filter,
                "items": [_serialize_recipient(user) for user in rows],
                "count": len(rows),
            },
        }
    )


# ----------------------------------------------------------------------------
# Send endpoint
# ----------------------------------------------------------------------------
@admin_notifications_bp.route("/broadcast", methods=["POST"])
@require_access_token
def broadcast() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    admin_user = _current_user()
    if admin_user is None:
        return _json({"success": False, "message": "Authentication required"}, 401)

    payload = request.get_json(silent=True) or {}

    mode = "single" if _safe_str(payload.get("mode")).lower() == "single" else "broadcast"

    raw_channels = payload.get("channels") or []
    channels = [
        channel.lower()
        for channel in raw_channels
        if isinstance(channel, str) and channel.lower() in {"sms", "email"}
    ]
    channels = list(dict.fromkeys(channels))

    subject = _safe_str(payload.get("subject"))
    message = _safe_str(payload.get("message"))
    audience = payload.get("audience") or {}

    if not message:
        return _json({"success": False, "message": "Message is required"}, 400)

    channel_error = _validate_channels(channels, mode)
    if channel_error:
        return _json({"success": False, "message": channel_error}, 400)

    recipients_list, role_filter, recipient_error = _resolve_recipients(mode=mode, audience=audience)
    if recipient_error:
        return _json({"success": False, "message": recipient_error}, 400)

    if not recipients_list:
        return _json({"success": False, "message": "No eligible recipients were found"}, 404)

    dispatch_id = str(uuid.uuid4())
    resolved_subject = _fallback_subject(subject, message)
    title = _dispatch_title(subject, mode, role_filter)
    audience_label = _audience_label(role_filter)

    in_app_enabled = _cfg_bool("IN_APP_NOTIFICATIONS_ENABLED", True)

    summary = {
        "dispatch_id": dispatch_id,
        "mode": mode,
        "audience_role": role_filter,
        "audience_label": audience_label,
        "recipient_count": len(recipients_list),
        "channels": channels,
        "subject": resolved_subject,
        "message_length": len(message),
        "in_app_created": 0,
        "sms_attempted": 0,
        "sms_sent": 0,
        "sms_failed": 0,
        "sms_skipped_no_phone": 0,
        "email_attempted": 0,
        "email_sent": 0,
        "email_failed": 0,
        "email_skipped_no_email": 0,
        "email_console_fallback": 0,
    }
    warnings: list[str] = []
    selected_recipient_payload: Optional[dict[str, Any]] = None

    try:
        for recipient in recipients_list:
            if mode == "single":
                selected_recipient_payload = _serialize_recipient(recipient)

            # -------------------------------------------------------------
            # Persist an in-app announcement with an explicit non-order type
            # only when in-app notifications are enabled.
            # -------------------------------------------------------------
            if in_app_enabled:
                notify_user(
                    getattr(recipient, "id"),
                    title,
                    message,
                    notification_type="admin_announcement",
                    actor_user_id=getattr(admin_user, "id"),
                    event_key=f"admin_announcement:{dispatch_id}:{getattr(recipient, 'id')}",
                    data=_build_announcement_payload(
                        recipient=recipient,
                        dispatch_id=dispatch_id,
                        mode=mode,
                        role_filter=role_filter,
                        channels=channels,
                        subject=resolved_subject,
                    ),
                    commit=False,
                )
                summary["in_app_created"] += 1

            if "sms" in channels:
                phone = _safe_str(getattr(recipient, "phone", None))
                if phone:
                    summary["sms_attempted"] += 1
                    sms_ok = bool(send_sms(to=phone, body=message))
                    _insert_sms_log(
                        user_id=getattr(recipient, "id"),
                        message=message,
                        context={
                            "dispatch_id": dispatch_id,
                            "origin": "admin_messaging",
                            "mode": mode,
                            "audience_role": role_filter,
                            "subject": resolved_subject,
                            "channel": "sms",
                        },
                        status="sent" if sms_ok else "failed",
                        error_text="" if sms_ok else "SMS provider reported failure",
                        sent=sms_ok,
                    )
                    if sms_ok:
                        summary["sms_sent"] += 1
                    else:
                        summary["sms_failed"] += 1
                else:
                    summary["sms_skipped_no_phone"] += 1

            if "email" in channels:
                email = _safe_str(getattr(recipient, "email", None))
                if email:
                    summary["email_attempted"] += 1
                    email_result = send_email_result(
                        to=email,
                        subject=resolved_subject,
                        body=message,
                        html=_build_email_html(heading=resolved_subject, message=message),
                    )

                    mode_name = _safe_str(email_result.get("mode"), "failed")
                    if mode_name == "smtp" and bool(email_result.get("delivered")):
                        summary["email_sent"] += 1
                    elif mode_name == "console_fallback":
                        summary["email_console_fallback"] += 1
                    else:
                        summary["email_failed"] += 1
                else:
                    summary["email_skipped_no_email"] += 1

        db.session.commit()

    except Exception as exc:
        db.session.rollback()
        return _json(
            {
                "success": False,
                "message": "Failed to process the administrative dispatch",
                "error": _safe_str(exc, "dispatch_error"),
            },
            500,
        )

    if not in_app_enabled:
        warnings.append("In-app notifications are disabled in system settings, so no bell/dashboard announcement was created.")

    if summary["email_console_fallback"] > 0:
        warnings.append(
            "Email SMTP is not configured. Email content was accepted only in console/dev fallback mode and was not delivered to real inboxes."
        )

    if summary["email_failed"] > 0:
        warnings.append(
            "One or more email deliveries failed. Review the backend mailer logs and SMTP configuration."
        )

    _audit_admin_view(
        action="admin_send_message",
        target_type="admin_messaging",
        metadata={
            "dispatch_id": dispatch_id,
            "mode": mode,
            "audience_role": role_filter,
            "channels": channels,
            "recipient_count": len(recipients_list),
        },
    )

    _audit_admin_governance(
        action="admin_message_dispatch",
        entity_type="admin_messaging",
        entity_id=dispatch_id,
        metadata={
            "dispatch_id": dispatch_id,
            "mode": mode,
            "audience_role": role_filter,
            "channels": channels,
            "message_length": len(message),
            "recipient_count": len(recipients_list),
            "sms_sent": summary["sms_sent"],
            "sms_failed": summary["sms_failed"],
            "email_sent": summary["email_sent"],
            "email_failed": summary["email_failed"],
            "email_console_fallback": summary["email_console_fallback"],
            "single_recipient_id": (
                selected_recipient_payload.get("id") if selected_recipient_payload else None
            ),
        },
    )

    if mode == "single":
        message_text = "Message sent successfully"
    else:
        message_text = "Broadcast dispatched successfully"

    if warnings:
        message_text = f"{message_text} with warnings"

    return _json(
        {
            "success": True,
            "message": message_text,
            "warnings": warnings,
            "meta": {
                **summary,
                "recipient": selected_recipient_payload,
            },
        }
    )