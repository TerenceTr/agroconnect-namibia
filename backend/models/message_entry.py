# ============================================================================
# backend/models/message_entry.py — Conversation Message Entry
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores each individual message posted inside a buyer/seller thread.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Text, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.db import db


class MessageEntry(db.Model):  # type: ignore[misc]
    __tablename__ = "message_entries"

    message_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    thread_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("message_threads.thread_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    sender_user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    body: Mapped[str] = mapped_column(Text, nullable=False)
    meta_json: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
        index=True,
    )

    thread = relationship("MessageThread", back_populates="messages")

    def to_dict(self) -> dict[str, Any]:
        return {
            "message_id": str(self.message_id),
            "thread_id": str(self.thread_id),
            "sender_user_id": str(self.sender_user_id),
            "body": self.body,
            "meta_json": self.meta_json or {},
            "is_system": bool(self.is_system),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
