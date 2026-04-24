# ============================================================================
# backend/models/admin_audit_event.py — Admin Governance Audit Model
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Canonical ORM model for privileged admin actions only.
#
# TABLE:
#   admin_audit_log
#
# DESIGN INTENT:
#   This model is the governance / privileged audit stream for actions such as:
#     • approve_product
#     • reject_product
#     • update_user_status
#     • update_order_status
#     • update_system_settings
#     • flush_cache
#
# IMPORTANT BOUNDARY:
#   - login_events         => auth/session events only
#   - user_activity_events => normal user/admin usage activity
#   - admin_audit_log      => privileged admin governance actions
#
# SCHEMA COMPATIBILITY:
#   The current database dump shows:
#     id uuid
#     admin_id uuid
#     action text
#     entity_type text
#     entity_id uuid
#     metadata jsonb
#     created_at timestamp
#
# SPECIAL NOTE ABOUT entity_id:
#   The DB column is UUID-backed, but some governance events may reference
#   non-UUID conceptual targets such as:
#     • "admin_settings"
#     • "application_cache"
#
#   To remain robust:
#     - UUID-like values are stored in entity_id normally
#     - non-UUID values are moved into metadata_json["entity_key"]
#       and entity_id is stored as NULL
#
#   This prevents flush/commit errors while preserving the target identity.
# ============================================================================
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, validates

from backend.database.db import db


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        text_value = str(value).strip()
    except Exception:
        return None
    return text_value or None


def _as_uuid(value: Any) -> Optional[uuid.UUID]:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value).strip())
    except Exception:
        return None


class AdminAuditLog(db.Model):
    """
    Privileged admin governance audit event.

    Examples:
      action="approve_product"
      action="reject_product"
      action="update_user_status"
      action="update_order_payment"
      action="update_system_settings"
    """

    __tablename__ = "admin_audit_log"

    # ------------------------------------------------------------------------
    # Primary key
    # ------------------------------------------------------------------------
    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # ------------------------------------------------------------------------
    # Admin actor
    # ------------------------------------------------------------------------
    admin_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # ------------------------------------------------------------------------
    # Governance action
    # ------------------------------------------------------------------------
    action: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
    )

    # ------------------------------------------------------------------------
    # Target classification
    # ------------------------------------------------------------------------
    entity_type: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True,
        index=True,
    )

    # ------------------------------------------------------------------------
    # Target identifier
    #
    # DB NOTE:
    #   Physical column is UUID-backed in the current schema.
    #   Non-UUID conceptual targets are redirected into metadata_json["entity_key"]
    #   by the validator below.
    # ------------------------------------------------------------------------
    entity_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        nullable=True,
        index=True,
    )

    # ------------------------------------------------------------------------
    # JSON payload
    # NOTE:
    #   The physical DB column is named "metadata", but Declarative models
    #   cannot safely use attribute name "metadata" because that collides with
    #   SQLAlchemy's class-level metadata. So we expose it as metadata_json.
    # ------------------------------------------------------------------------
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column(
        "metadata",
        JSONB,
        nullable=True,
    )

    # ------------------------------------------------------------------------
    # Event timestamp
    # ------------------------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
        default=datetime.utcnow,
        index=True,
    )

    @validates("entity_id")
    def _validate_entity_id(self, _key: str, value: Any) -> Optional[uuid.UUID]:
        """
        Accept UUIDs normally.

        If a non-UUID value is supplied:
          - preserve it in metadata_json["entity_key"]
          - store NULL in entity_id so the DB write succeeds

        This makes routes/services resilient even when governance events refer
        to conceptual system targets instead of row-backed entities.
        """
        if value is None or value == "":
            return None

        parsed = _as_uuid(value)
        if parsed is not None:
            return parsed

        entity_key = _safe_str(value)
        if entity_key:
            current = dict(self.metadata_json or {})
            current.setdefault("entity_key", entity_key)
            self.metadata_json = current

        return None

    @property
    def resolved_entity_id(self) -> Optional[str]:
        """
        Frontend-friendly entity identifier.

        Preference order:
          1. UUID in entity_id
          2. metadata_json["entity_key"]
        """
        if self.entity_id is not None:
            return str(self.entity_id)

        meta = self.metadata_json or {}
        entity_key = meta.get("entity_key")
        return str(entity_key) if entity_key is not None else None

    def to_dict(self) -> dict[str, Any]:
        """
        Stable serialized payload for audit APIs.
        """
        return {
            "id": str(self.id),
            "admin_id": str(self.admin_id),
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.resolved_entity_id,
            "metadata": self.metadata_json or {},
            "metadata_json": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }