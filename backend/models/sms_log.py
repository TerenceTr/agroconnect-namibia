# ====================================================================
# backend/models/sms_log.py — SMS Audit Log (DB-Aligned + MAPPER-SAFE)
# ====================================================================
# FILE ROLE:
#   • Stores outbound SMS audit rows (table: sms_logs)
#   • Used by admin broadcast + reporting pages
#   • Acts as an audit trail for queued/sent/failed SMS events
#
# THIS FIX MATTERS:
#   SmsLog.user uses back_populates="sms_logs"
#   -> User MUST define `sms_logs` relationship or SQLAlchemy mapper will crash.
# ====================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional, TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from backend.database.db import db

if TYPE_CHECKING:
    from .user import User


def utc_now() -> datetime:
    """
    Naive UTC timestamp (timestamp without time zone).

    Keep consistent with DateTime(timezone=False) used across your schema.
    """
    return datetime.utcnow()


class SmsLog(db.Model):  # type: ignore[misc]
    __tablename__ = "sms_logs"

    # ---------------------------- Identity ----------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ---------------------------- Foreign Keys ------------------------
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # ---------------------------- Columns -----------------------------
    phone_number: Mapped[str] = mapped_column(String(20), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    # expected values: queued | sent | failed
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")

    # DB default now() + Python fallback utc_now()
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
        default=utc_now,
        index=True,
    )

    # ---------------------------- Relationships -----------------------
    user: Mapped[Optional["User"]] = relationship(
        "User",
        back_populates="sms_logs",
        foreign_keys=[user_id],
        passive_deletes=True,
        lazy="selectin",
    )

    # ---------------------------- Serialization -----------------------
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": str(self.id),
            "user_id": str(self.user_id) if self.user_id else None,
            "phone_number": self.phone_number,
            "message": self.message,
            "status": self.status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
