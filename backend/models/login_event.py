# ============================================================================
# backend/models/login_event.py — Authentication Session Event Model
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Canonical ORM model for authentication/session events only.
#
# DESIGN INTENT:
#   This table is NO LONGER treated as a generic "presence" or "seen" log.
#   It is reserved for true auth/session events such as:
#     • login
#     • logout
#     • logout_all
#     • refresh
#     • failed_login
#     • session_expired
#     • token_revoked
#
# IMPORTANT ARCHITECTURE RULE:
#   Presence / heartbeat activity must NOT be written here.
#   "Who is online now?" belongs to:
#     • users.last_seen_at
#     • presence store / presence cache
#   not to login_events.
#
# WHY THIS CHANGE:
#   The previous design mixed "seen" heartbeat writes with real login history,
#   which polluted reporting and made login statistics inaccurate.
#
# COMPATIBILITY:
#   ✅ Keeps the existing table name: login_events
#   ✅ Keeps the existing columns found in the current database dump:
#        id, user_id, event_type, ip_address, user_agent, created_at
#   ✅ Safe to use before the later audit/reporting files are updated
# ============================================================================
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Final, Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from backend.database.db import db

# ----------------------------------------------------------------------------
# Canonical auth/session event names
# ----------------------------------------------------------------------------
AUTH_EVENT_LOGIN: Final[str] = "login"
AUTH_EVENT_LOGOUT: Final[str] = "logout"
AUTH_EVENT_LOGOUT_ALL: Final[str] = "logout_all"
AUTH_EVENT_REFRESH: Final[str] = "refresh"
AUTH_EVENT_FAILED_LOGIN: Final[str] = "failed_login"
AUTH_EVENT_SESSION_EXPIRED: Final[str] = "session_expired"
AUTH_EVENT_TOKEN_REVOKED: Final[str] = "token_revoked"

VALID_AUTH_EVENT_TYPES: Final[tuple[str, ...]] = (
    AUTH_EVENT_LOGIN,
    AUTH_EVENT_LOGOUT,
    AUTH_EVENT_LOGOUT_ALL,
    AUTH_EVENT_REFRESH,
    AUTH_EVENT_FAILED_LOGIN,
    AUTH_EVENT_SESSION_EXPIRED,
    AUTH_EVENT_TOKEN_REVOKED,
)


class LoginEvent(db.Model):
    """
    Represents a single authentication/session event.

    IMPORTANT:
      This model is intentionally limited to auth/session history.
      Do not write heartbeat / route-visit / general user activity rows here.

    Typical examples:
      - "login"
      - "logout"
      - "failed_login"
      - "refresh"
    """

    __tablename__ = "login_events"

    # ------------------------------------------------------------------------
    # Primary key
    # ------------------------------------------------------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ------------------------------------------------------------------------
    # User who triggered the auth/session event
    # ------------------------------------------------------------------------
    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ------------------------------------------------------------------------
    # Event classification
    # NOTE:
    #   We keep this as a plain String(40) for compatibility with the existing
    #   schema. Validation is enforced in service/route code.
    # ------------------------------------------------------------------------
    event_type: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default=AUTH_EVENT_LOGIN,
        index=True,
    )

    # ------------------------------------------------------------------------
    # Best-effort request context
    # ------------------------------------------------------------------------
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)

    # ------------------------------------------------------------------------
    # Event timestamp
    # ------------------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    def to_dict(self) -> dict[str, Optional[str]]:
        """
        Serialize for admin reporting / audit APIs.
        """
        return {
            "id": str(self.id),
            "user_id": str(self.user_id),
            "event_type": self.event_type,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    @property
    def is_login_like(self) -> bool:
        """
        True for successful session-start style events.
        """
        return self.event_type in (AUTH_EVENT_LOGIN, AUTH_EVENT_REFRESH)

    @property
    def is_logout_like(self) -> bool:
        """
        True for explicit or forced session-end style events.
        """
        return self.event_type in (
            AUTH_EVENT_LOGOUT,
            AUTH_EVENT_LOGOUT_ALL,
            AUTH_EVENT_SESSION_EXPIRED,
            AUTH_EVENT_TOKEN_REVOKED,
        )