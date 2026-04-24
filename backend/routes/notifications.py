# ============================================================================
# backend/routes/notifications.py — Persisted Notification Feed API
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Auth-scoped notification endpoints for the bell feed.
#
# ROUTES:
#   GET  /api/notifications
#   GET  /api/notifications/me
#   POST /api/notifications/mark-read
#   POST /api/notifications/mark_read
#   POST /api/notifications/clear
#
# THIS UPDATE:
#   ✅ Supports seller-friendly category filtering:
#        orders | messages | moderation | announcements
#   ✅ Returns unread breakdown by category for topbar tabs
#   ✅ Lets clients mark or clear one category at a time
# ============================================================================

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify

from backend.models.user import User
from backend.services.notifications import (
    clear_notifications,
    get_unread_notification_breakdown,
    get_unread_notification_count,
    list_user_notifications,
    mark_notifications_read,
)
from backend.utils.require_auth import require_access_token

notifications_bp = Blueprint("notifications", __name__)

VALID_NOTIFICATION_CATEGORIES = {"orders", "messages", "moderation", "announcements"}


def _safe_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _normalize_category(v: Any) -> Optional[str]:
    value = (_safe_str(v) or "").lower()
    return value if value in VALID_NOTIFICATION_CATEGORIES else None


def _is_truthy(v: Any) -> bool:
    s = (_safe_str(v) or "").lower()
    return s in {"1", "true", "yes", "y", "on"}


def _to_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _as_uuid(v: Any) -> Optional[UUID]:
    if isinstance(v, UUID):
        return v
    s = _safe_str(v)
    if not s:
        return None
    try:
        return UUID(s)
    except Exception:
        return None


def _user_id(user: User) -> Optional[UUID]:
    return _as_uuid(getattr(user, "id", None) or getattr(user, "user_id", None))


def token_required(fn):
    @require_access_token
    def wrapper(*args, **kwargs):
        user = getattr(request, "current_user", None)
        if not isinstance(user, User):
            return jsonify({"ok": False, "message": "Unauthorized"}), 401
        return fn(user, *args, **kwargs)

    wrapper.__name__ = getattr(fn, "__name__", "wrapped_notifications")
    return wrapper


def _extract_ids(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    if isinstance(raw, str):
        return [x.strip() for x in raw.split(",") if x.strip()]
    return []


@notifications_bp.get("")
@notifications_bp.get("/")
@notifications_bp.get("/me")
@token_required
def get_my_notifications(current_user: User):
    user_id = _user_id(current_user)
    if user_id is None:
        return jsonify({"ok": False, "message": "Invalid authenticated user context"}), 401

    limit = max(1, min(_to_int(request.args.get("limit", 30), 30), 200))
    unread_only = _is_truthy(request.args.get("unread_only"))
    category = _normalize_category(request.args.get("category"))

    rows = list_user_notifications(
        user_id,
        limit=limit,
        unread_only=unread_only,
        category=category,
    )

    unread_count = get_unread_notification_count(user_id)
    unread_by_category = get_unread_notification_breakdown(user_id)

    return jsonify(
        {
            "ok": True,
            "data": rows,
            "unread_count": unread_count,
            "unread_by_category": unread_by_category,
            "category": category,
        }
    ), 200


@notifications_bp.post("/mark-read")
@notifications_bp.post("/mark_read")
@token_required
def mark_my_notifications_read(current_user: User):
    user_id = _user_id(current_user)
    if user_id is None:
        return jsonify({"ok": False, "message": "Invalid authenticated user context"}), 401

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        payload = {}

    ids = _extract_ids(payload.get("notification_ids"))
    mark_all = bool(payload.get("mark_all"))
    category = _normalize_category(payload.get("category"))

    changed = mark_notifications_read(
        user_id,
        notification_ids=ids,
        mark_all=mark_all,
        category=category,
        commit=True,
    )

    unread_count = get_unread_notification_count(user_id)
    unread_by_category = get_unread_notification_breakdown(user_id)

    return jsonify(
        {
            "ok": True,
            "message": "Notifications updated",
            "changed": changed,
            "unread_count": unread_count,
            "unread_by_category": unread_by_category,
            "category": category,
        }
    ), 200


@notifications_bp.post("/clear")
@token_required
def clear_my_notifications(current_user: User):
    user_id = _user_id(current_user)
    if user_id is None:
        return jsonify({"ok": False, "message": "Invalid authenticated user context"}), 401

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        payload = {}

    ids = _extract_ids(payload.get("notification_ids"))
    clear_all = bool(payload.get("clear_all"))
    category = _normalize_category(payload.get("category"))

    deleted = clear_notifications(
        user_id,
        notification_ids=ids,
        clear_all=clear_all,
        category=category,
        commit=True,
    )

    unread_count = get_unread_notification_count(user_id)
    unread_by_category = get_unread_notification_breakdown(user_id)

    return jsonify(
        {
            "ok": True,
            "message": "Notifications cleared",
            "deleted": deleted,
            "unread_count": unread_count,
            "unread_by_category": unread_by_category,
            "category": category,
        }
    ), 200
