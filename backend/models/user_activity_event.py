# ============================================================================
# backend/models/user_activity_event.py — User Activity Audit Event Model
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Canonical ORM model for non-auth user activity after a user is logged in.
#
# DESIGN INTENT:
#   This table captures "what the user did on the system" and is separate from:
#     • login_events       -> authentication/session history only
#     • admin_audit_log    -> privileged governance/admin actions
#
# EXAMPLES OF ACTIVITY EVENTS:
#   Customer:
#     • viewed product
#     • added item to cart
#     • updated cart quantity
#     • started checkout
#     • placed order
#     • uploaded payment proof
#     • submitted rating
#
#   Farmer:
#     • created product
#     • updated product
#     • viewed orders
#     • set delivery fee
#     • updated payment profile
#     • marked order ready
#
#   Admin (non-governance browsing activity):
#     • viewed analytics page
#     • opened audit log
#     • opened reports page
#
# IMPORTANT BOUNDARY:
#   Do NOT use this model for:
#     • login/logout history              -> login_events
#     • admin moderation/governance write -> admin_audit_log
#
# WHY THIS EXISTS:
#   A master's-level audit design should separate:
#     1. session/auth events
#     2. user activity events
#     3. governance / privileged audit events
#
# COMPATIBILITY:
#   ✅ New table, so it does not break existing code immediately
#   ✅ Flexible metadata_json payload for evolving frontend/backend actions
# ============================================================================
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Final, Optional

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db

# ----------------------------------------------------------------------------
# Common outcome values
# ----------------------------------------------------------------------------
ACTIVITY_STATUS_SUCCESS: Final[str] = "success"
ACTIVITY_STATUS_FAILED: Final[str] = "failed"
ACTIVITY_STATUS_BLOCKED: Final[str] = "blocked"

VALID_ACTIVITY_STATUSES: Final[tuple[str, ...]] = (
    ACTIVITY_STATUS_SUCCESS,
    ACTIVITY_STATUS_FAILED,
    ACTIVITY_STATUS_BLOCKED,
)

# ----------------------------------------------------------------------------
# Common target types (guidance only, not strict enum at DB level)
# ----------------------------------------------------------------------------
TARGET_TYPE_PRODUCT: Final[str] = "product"
TARGET_TYPE_ORDER: Final[str] = "order"
TARGET_TYPE_CART: Final[str] = "cart"
TARGET_TYPE_PAYMENT: Final[str] = "payment"
TARGET_TYPE_RATING: Final[str] = "rating"
TARGET_TYPE_PROFILE: Final[str] = "profile"
TARGET_TYPE_PAGE: Final[str] = "page"
TARGET_TYPE_REPORT: Final[str] = "report"
TARGET_TYPE_NOTIFICATION: Final[str] = "notification"
TARGET_TYPE_USER: Final[str] = "user"


class UserActivityEvent(db.Model):
    """
    Represents a non-auth activity performed by a signed-in user.

    This is the primary source for answering:
      - what each user did after login
      - what page/API/action was used
      - whether the action succeeded or failed
      - what domain entity was affected

    Examples:
      action="view_product"
      action="add_to_cart"
      action="place_order"
      action="product_created"
      action="delivery_fee_set"
      action="upload_payment_proof"
    """

    __tablename__ = "user_activity_events"

    # ------------------------------------------------------------------------
    # Primary key
    # ------------------------------------------------------------------------
    event_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ------------------------------------------------------------------------
    # Actor
    # ------------------------------------------------------------------------
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ------------------------------------------------------------------------
    # Session/request correlation
    # NOTE:
    #   session_id is app-generated and nullable for backward compatibility.
    #   request_id can be injected by middleware later to trace one request
    #   across logs and DB events.
    # ------------------------------------------------------------------------
    session_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)

    # ------------------------------------------------------------------------
    # Role snapshot
    # NOTE:
    #   Store the role at the time of the action for reporting convenience.
    #   This avoids expensive historical reconstruction if a user's role later
    #   changes.
    # ------------------------------------------------------------------------
    role_name: Mapped[Optional[str]] = mapped_column(String(40), nullable=True, index=True)

    # ------------------------------------------------------------------------
    # Activity definition
    # ------------------------------------------------------------------------
    action: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    target_type: Mapped[Optional[str]] = mapped_column(String(60), nullable=True, index=True)
    target_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    # ------------------------------------------------------------------------
    # Request context
    # ------------------------------------------------------------------------
    route: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    http_method: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # ------------------------------------------------------------------------
    # Outcome / error context
    # ------------------------------------------------------------------------
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=ACTIVITY_STATUS_SUCCESS,
        index=True,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # ------------------------------------------------------------------------
    # Flexible payload for domain details
    # Examples:
    #   {"product_name": "Tomatoes", "qty": 3}
    #   {"order_id": "...", "payment_method": "eft"}
    #   {"page": "/dashboard/admin/analytics", "section": "top_products"}
    # ------------------------------------------------------------------------
    metadata_json: Mapped[Optional[dict]] = mapped_column(JSONB, nullable=True)

    # ------------------------------------------------------------------------
    # Event timestamp
    # ------------------------------------------------------------------------
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    __table_args__ = (
        Index("ix_user_activity_events_user_time", "user_id", "occurred_at"),
        Index("ix_user_activity_events_action_time", "action", "occurred_at"),
        Index("ix_user_activity_events_role_time", "role_name", "occurred_at"),
    )

    def to_dict(self) -> dict[str, object]:
        """
        Serialize for admin audit/reporting endpoints.
        """
        return {
            "event_id": str(self.event_id),
            "user_id": str(self.user_id),
            "session_id": self.session_id,
            "request_id": self.request_id,
            "role_name": self.role_name,
            "action": self.action,
            "target_type": self.target_type,
            "target_id": str(self.target_id) if self.target_id else None,
            "route": self.route,
            "http_method": self.http_method,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "status": self.status,
            "error_message": self.error_message,
            "metadata_json": self.metadata_json or {},
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
        }

    @property
    def is_success(self) -> bool:
        return self.status == ACTIVITY_STATUS_SUCCESS

    @property
    def is_failed(self) -> bool:
        return self.status == ACTIVITY_STATUS_FAILED

    @property
    def display_target(self) -> str:
        """
        Friendly summary for UI tables.
        """
        if self.target_type and self.target_id:
            return f"{self.target_type}:{self.target_id}"
        if self.target_type:
            return self.target_type
        return "system"