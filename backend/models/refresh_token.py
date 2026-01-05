# ====================================================================
# backend/models/refresh_token.py — Refresh Token Store
# ====================================================================
# FILE ROLE:
#   • Optional persistent refresh-token storage
#   • Supports multi-device sessions & token revocation
#
# NOTES:
#   • Keep this model if you plan to implement refresh tokens
#   • Safe even if not currently used by routes/services
# ====================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.db import db


def utc_now_naive() -> datetime:
    return datetime.utcnow()


class RefreshToken(db.Model):
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

    device_id: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime())

    user = relationship("User", back_populates="refresh_tokens", lazy="joined")
