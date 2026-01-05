# ============================================================================
# backend/routes/admin_notifications.py — Admin Broadcasts (JWT)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin endpoint to broadcast notifications to users.
#   Current implementation:
#     • SMS: logs messages into sms_logs (DB dump table exists)
#     • Email: accepted placeholder for UI compatibility
#
# ENDPOINT:
#   POST /admin/notifications/broadcast
#   payload: { channels: ['sms','email'], subject?, message, audience: { role } }
# ============================================================================

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import select, text

from backend.database.db import db
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User
from backend.utils.require_auth import require_access_token

admin_notifications_bp = Blueprint("admin_notifications", __name__)


def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _current_user() -> Optional[User]:
    u = getattr(g, "current_user", None)
    return u if isinstance(u, User) else None


def _admin_guard() -> Optional[Response]:
    u = _current_user()
    if u is None:
        return _json({"success": False, "message": "Authentication required"}, 401)
    if getattr(u, "role", None) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)
    return None


@admin_notifications_bp.route("/broadcast", methods=["POST"])
@require_access_token
def broadcast() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    payload = request.get_json(silent=True) or {}
    channels = payload.get("channels") or []
    subject = (payload.get("subject") or "").strip()
    message = (payload.get("message") or "").strip()
    audience = payload.get("audience") or {}
    role = (audience.get("role") or "all").strip().lower()

    if not message:
        return _json({"success": False, "message": "Message is required"}, 400)

    channels = [c.lower() for c in channels if isinstance(c, str)]
    if not channels:
        return _json({"success": False, "message": "Select at least one channel"}, 400)

    # Resolve recipients (active + not soft-deleted)
    q = select(User).where(User.is_active.is_(True))  # type: ignore[attr-defined]
    q = q.where(User.deleted_at.is_(None))  # type: ignore[attr-defined]

    if role in ("farmers", "farmer"):
        q = q.where(User.role == ROLE_FARMER)
    elif role in ("customers", "customer"):
        q = q.where(User.role == ROLE_CUSTOMER)
    elif role in ("admins", "admin"):
        q = q.where(User.role == ROLE_ADMIN)

    recipients = db.session.execute(q).scalars().all()

    sms_logged = 0
    email_accepted = 0

    # SMS logging into sms_logs (DB dump columns)
    if "sms" in channels:
        for u in recipients:
            # sms_logs has user_id, message_content, timestamp, status, template_name, context, provider, attempt_count
            ctx = {
                "subject": subject,
                "audience_role": role,
                "origin": "admin_broadcast",
            }
            db.session.execute(
                text(
                    "INSERT INTO public.sms_logs "
                    "(user_id, message_content, timestamp, status, template_name, context, provider, attempt_count) "
                    "VALUES (:user_id, :message_content, :timestamp, :status, :template_name, CAST(:context AS jsonb), :provider, :attempt_count)"
                ),
                {
                    "user_id": str(u.id),
                    "message_content": message,
                    "timestamp": datetime.utcnow(),
                    "status": "queued",
                    "template_name": "admin_broadcast",
                    "context": json.dumps(ctx),
                    "provider": "internal",
                    "attempt_count": 0,
                },
            )
            sms_logged += 1

    # Email placeholder (accepted for UI compatibility)
    if "email" in channels:
        email_accepted = len(recipients)

    db.session.commit()
    return _json(
        {
            "success": True,
            "message": "Broadcast accepted",
            "meta": {
                "recipients": len(recipients),
                "sms_logged": sms_logged,
                "email_accepted": email_accepted,
                "subject": subject,
                "audience_role": role,
            },
        },
        200,
    )
