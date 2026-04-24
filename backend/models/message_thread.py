# ============================================================================
# backend/models/message_thread.py — Buyer/Seller Conversation Thread
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Durable two-party conversation metadata for AgroConnect messaging.
#
# DESIGN:
#   • One thread belongs to exactly one customer + one farmer
#   • Optional commerce context can be attached via product_id / order_id
#   • Per-user read timestamps drive unread badges without a join table
#   • last_message_* fields keep inbox queries fast and UI-friendly
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, String, Text, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.database.db import db


class MessageThread(db.Model):  # type: ignore[misc]
    __tablename__ = "message_threads"

    thread_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )

    customer_user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    farmer_user_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    product_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("products.product_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    order_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("orders.order_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    subject: Mapped[str] = mapped_column(String(180), nullable=False, server_default=text("'Conversation'"))
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default=text("'open'"), index=True)

    last_message_preview: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    last_message_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
        index=True,
    )
    last_message_sender_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    customer_last_read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)
    farmer_last_read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=False), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=text("now()"),
    )

    messages = relationship(
        "MessageEntry",
        back_populates="thread",
        cascade="all, delete-orphan",
        order_by="MessageEntry.created_at.asc()",
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "thread_id": str(self.thread_id),
            "customer_user_id": str(self.customer_user_id),
            "farmer_user_id": str(self.farmer_user_id),
            "product_id": str(self.product_id) if self.product_id else None,
            "order_id": str(self.order_id) if self.order_id else None,
            "subject": self.subject,
            "status": self.status,
            "last_message_preview": self.last_message_preview,
            "last_message_at": self.last_message_at.isoformat() if self.last_message_at else None,
            "last_message_sender_id": str(self.last_message_sender_id) if self.last_message_sender_id else None,
            "customer_last_read_at": self.customer_last_read_at.isoformat() if self.customer_last_read_at else None,
            "farmer_last_read_at": self.farmer_last_read_at.isoformat() if self.farmer_last_read_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
