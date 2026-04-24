# ============================================================================
# backend/services/notifications.py — Notification Persistence Service
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Shared notification CRUD/service helpers for persisted bell feeds.
#
# PUBLIC FUNCTIONS:
#   • notify_user(...)
#   • list_user_notifications(...)
#   • get_unread_notification_count(...)
#   • get_unread_notification_breakdown(...)
#   • mark_notifications_read(...)
#   • clear_notifications(...)
# ============================================================================

from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Optional
from uuid import UUID

from backend.database.db import db
from backend.extensions import socketio
from backend.models.notification import Notification, classify_notification_category

VALID_NOTIFICATION_CATEGORIES = {"orders", "messages", "moderation", "announcements"}


def _emit_notification_change(user_id: UUID, *, category: Optional[str] = None) -> None:
    """Emit a lightweight realtime hint so topbar bells can refresh immediately."""
    try:
        room = f"user:{user_id}"
        payload = {
            "user_id": str(user_id),
            "category": _normalize_category(category),
            "unread_count": get_unread_notification_count(user_id),
            "unread_by_category": get_unread_notification_breakdown(user_id),
        }
        socketio.emit("notifications:changed", payload, room=room, namespace="/notifications")
    except Exception:
        # Realtime emit must never block the main request flow.
        return None


def _safe_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _as_uuid(v: Any) -> Optional[UUID]:
    if v is None:
        return None
    if isinstance(v, UUID):
        return v
    s = _safe_str(v)
    if not s:
        return None
    try:
        return UUID(s)
    except Exception:
        return None


def _utcnow() -> datetime:
    return datetime.utcnow()


def _normalize_data(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    return {}


def _normalize_category(category: Any) -> Optional[str]:
    value = (_safe_str(category) or "").lower()
    return value if value in VALID_NOTIFICATION_CATEGORIES else None


def _matches_category(row: Notification, category: Optional[str]) -> bool:
    if not category:
        return True
    return classify_notification_category(row.notification_type, row.data_json or {}) == category


def serialize_notification(row: Notification) -> dict[str, object]:
    return row.to_dict()


def notify_user(
    user_id: UUID,
    subject: str,
    message: str = "",
    *,
    notification_type: str = "system",
    order_id: Any = None,
    actor_user_id: Any = None,
    event_key: Optional[str] = None,
    data: Optional[dict[str, Any]] = None,
    commit: bool = True,
) -> dict[str, object]:
    """
    Create or refresh a persisted notification.

    DEDUPE RULE:
      If event_key is provided, one user gets at most one row per event_key.
      Re-firing the same event will refresh the row and mark it unread again.
    """
    uid = _as_uuid(user_id)
    if uid is None:
        raise ValueError("user_id is required")

    title = _safe_str(subject)
    if not title:
        raise ValueError("subject is required")

    order_uuid = _as_uuid(order_id)
    actor_uuid = _as_uuid(actor_user_id)
    clean_event_key = _safe_str(event_key)
    clean_type = _safe_str(notification_type) or "system"
    payload = _normalize_data(data)

    row: Optional[Notification] = None

    if clean_event_key:
        row = (
            db.session.query(Notification)
            .filter(
                Notification.user_id == uid,
                Notification.event_key == clean_event_key,
            )
            .one_or_none()
        )

    if row is None:
        row = Notification()
        row.user_id = uid
        db.session.add(row)

    row.actor_user_id = actor_uuid
    row.order_id = order_uuid
    row.notification_type = clean_type
    row.title = title
    row.message = _safe_str(message)
    row.event_key = clean_event_key
    row.data_json = payload
    row.is_read = False
    row.read_at = None
    row.updated_at = _utcnow()

    if commit:
        db.session.commit()
        db.session.refresh(row)
        _emit_notification_change(uid, category=classify_notification_category(clean_type, payload))

    return serialize_notification(row)


def list_user_notifications(
    user_id: UUID,
    *,
    limit: int = 30,
    unread_only: bool = False,
    category: Optional[str] = None,
) -> list[dict[str, object]]:
    uid = _as_uuid(user_id)
    if uid is None:
        return []

    safe_limit = max(1, min(int(limit or 30), 200))
    normalized_category = _normalize_category(category)

    q = (
        db.session.query(Notification)
        .filter(Notification.user_id == uid)
        .order_by(Notification.created_at.desc(), Notification.notification_id.desc())
    )

    if unread_only:
        q = q.filter(Notification.is_read.is_(False))

    rows = q.limit(max(safe_limit * 4, safe_limit)).all()
    filtered = [r for r in rows if _matches_category(r, normalized_category)]
    return [serialize_notification(r) for r in filtered[:safe_limit]]


def get_unread_notification_count(user_id: UUID, *, category: Optional[str] = None) -> int:
    uid = _as_uuid(user_id)
    if uid is None:
        return 0

    normalized_category = _normalize_category(category)
    rows = (
        db.session.query(Notification)
        .filter(
            Notification.user_id == uid,
            Notification.is_read.is_(False),
        )
        .all()
    )
    if not normalized_category:
        return len(rows)
    return sum(1 for row in rows if _matches_category(row, normalized_category))


def get_unread_notification_breakdown(user_id: UUID) -> dict[str, int]:
    uid = _as_uuid(user_id)
    if uid is None:
        return {"orders": 0, "messages": 0, "moderation": 0, "announcements": 0}

    rows = (
        db.session.query(Notification)
        .filter(
            Notification.user_id == uid,
            Notification.is_read.is_(False),
        )
        .all()
    )

    breakdown = {"orders": 0, "messages": 0, "moderation": 0, "announcements": 0}
    for row in rows:
        category = classify_notification_category(row.notification_type, row.data_json or {})
        if category in breakdown:
            breakdown[category] += 1
    return breakdown


def mark_notifications_read(
    user_id: UUID,
    *,
    notification_ids: Optional[Iterable[Any]] = None,
    mark_all: bool = False,
    category: Optional[str] = None,
    commit: bool = True,
) -> int:
    uid = _as_uuid(user_id)
    if uid is None:
        return 0

    normalized_category = _normalize_category(category)
    q = db.session.query(Notification).filter(Notification.user_id == uid)

    if not mark_all:
        ids = [_as_uuid(x) for x in (notification_ids or [])]
        ids = [x for x in ids if x is not None]
        if not ids:
            return 0
        q = q.filter(Notification.notification_id.in_(ids))

    rows = [row for row in q.all() if _matches_category(row, normalized_category)]
    now = _utcnow()

    changed = 0
    for row in rows:
        if not row.is_read:
            row.is_read = True
            row.read_at = now
            row.updated_at = now
            changed += 1

    if commit:
        db.session.commit()
        if changed > 0:
            _emit_notification_change(uid, category=normalized_category)

    return changed


def clear_notifications(
    user_id: UUID,
    *,
    notification_ids: Optional[Iterable[Any]] = None,
    clear_all: bool = False,
    category: Optional[str] = None,
    commit: bool = True,
) -> int:
    uid = _as_uuid(user_id)
    if uid is None:
        return 0

    normalized_category = _normalize_category(category)
    q = db.session.query(Notification).filter(Notification.user_id == uid)

    if not clear_all:
        ids = [_as_uuid(x) for x in (notification_ids or [])]
        ids = [x for x in ids if x is not None]
        if not ids:
            return 0
        q = q.filter(Notification.notification_id.in_(ids))

    rows = [row for row in q.all() if _matches_category(row, normalized_category)]
    deleted = len(rows)

    for row in rows:
        db.session.delete(row)

    if commit:
        db.session.commit()
        if deleted > 0:
            _emit_notification_change(uid, category=normalized_category)

    return deleted
