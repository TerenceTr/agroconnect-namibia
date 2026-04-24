# ============================================================================
# backend/models/notification.py — Persisted In-App Notifications
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Durable notification row for server-side bell feeds.
#
# DESIGN:
#   • One row = one user-visible notification
#   • event_key supports dedupe per user
#   • data_json stores event-specific UI payload
#   • category is derived at serialization time so we do not need a migration
#
# CATEGORY MODEL FOR SELLER UX:
#   • orders
#   • messages
#   • moderation
#   • announcements
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db


ORDERS_NOTIFICATION_TYPES = {
    "new_order",
    "payment_proof",
    "payment_submitted",
    "order_ready_for_payment",
    "delivery_fee_set",
    "delivery_due_today",
    "order_cancelled",
    "order_completed",
    "refund_requested",
}

MESSAGE_NOTIFICATION_TYPES = {
    "customer_message_received",
    "support_reply",
}

ANNOUNCEMENT_NOTIFICATION_TYPES = {
    "admin_message",
    "admin_announcement",
    "announcement",
    "broadcast",
}

MODERATION_NOTIFICATION_TYPES = {
    "product_review",
    "product_approved",
    "product_rejected",
    "product_edit_required",
    "policy_flagged",
}


def classify_notification_category(
    notification_type: Optional[str],
    data_json: Optional[dict[str, Any]] = None,
) -> str:
    payload = data_json if isinstance(data_json, dict) else {}
    explicit = str(payload.get("category") or "").strip().lower()
    if explicit in {"orders", "messages", "moderation", "announcements", "announcement"}:
        return "announcements" if explicit.startswith("announcement") else explicit

    ntype = str(notification_type or "").strip().lower()
    if ntype in ORDERS_NOTIFICATION_TYPES:
        return "orders"
    if ntype in MESSAGE_NOTIFICATION_TYPES:
        return "messages"
    if ntype in ANNOUNCEMENT_NOTIFICATION_TYPES:
        return "announcements"
    if ntype in MODERATION_NOTIFICATION_TYPES:
        return "moderation"

    # Reasonable default for unmatched operational items.
    return "orders"


class Notification(db.Model):  # type: ignore[misc]
    __tablename__ = "notifications"

    notification_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    actor_user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    order_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("orders.order_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    notification_type: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    event_key: Mapped[Optional[str]] = mapped_column(String(191), nullable=True)
    data_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    is_read: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    read_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=False),
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
    )

    def to_dict(self) -> dict[str, object]:
        payload = self.data_json or {}
        return {
            "notification_id": str(self.notification_id),
            "user_id": str(self.user_id),
            "actor_user_id": str(self.actor_user_id) if self.actor_user_id else None,
            "order_id": str(self.order_id) if self.order_id else None,
            "notification_type": self.notification_type,
            "title": self.title,
            "message": self.message,
            "event_key": self.event_key,
            "data_json": payload,
            "category": classify_notification_category(self.notification_type, payload),
            "is_read": bool(self.is_read),
            "read_at": self.read_at.isoformat() if self.read_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
