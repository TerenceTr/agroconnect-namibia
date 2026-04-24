# ============================================================================
# backend/models/refresh_token.py — Refresh Token Persistence Model
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Persists refresh tokens for long-lived sessions.
#
# WHY THIS EXISTS:
#   ✅ server-side revocation
#   ✅ refresh-token rotation
#   ✅ session invalidation ("logout all devices")
#
# IMPORTANT:
#   This model requires a real `refresh_tokens` table in the database.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from backend.models.user import User


class RefreshToken(db.Model):  # type: ignore[misc]
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Store token hash only, never raw token
    token_hash: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    user: Mapped["User"] = relationship("User", back_populates="refresh_tokens")

    @staticmethod
    def default_expiry(days: int = 30) -> datetime:
        return datetime.now(timezone.utc) + timedelta(days=max(1, days))

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None

    @property
    def is_expired(self) -> bool:
        return self.expires_at <= datetime.now(timezone.utc)

    @property
    def is_active_token(self) -> bool:
        return (not self.is_revoked) and (not self.is_expired)

    def revoke(self) -> None:
        if self.revoked_at is None:
            self.revoked_at = datetime.now(timezone.utc)