# ============================================================================
# backend/models/product_moderation_event.py — Product Moderation Event Log
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Stores moderation-relevant submission/edit/review events.
#   Used for:
#     ✅ Admin "Changed fields" diff (what farmer edited)
#     ✅ SLA analytics based on last resubmission time
# ----------------------------------------------------------------------------
# EVENTS:
#   submitted        = farmer creates a product (pending)
#   resubmitted      = public/rejected product edited => pending again
#   updated_pending  = still pending but farmer edited key fields again
#   approved         = admin approves => available
#   rejected         = admin rejects => rejected + reason
#
# THIS VERSION FIXES:
#   ✅ Pyright error on json.loads(self.changed_fields_json or "[]")
#   ✅ Safe JSON decoding from SQLAlchemy text columns
#   ✅ Adds typed getters for before/after payloads
# ============================================================================

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List

from backend.database.db import db


class ProductModerationEvent(db.Model):
    __tablename__ = "product_moderation_events"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    product_id = db.Column(
        db.String(36),
        db.ForeignKey("products.product_id"),
        nullable=False,
        index=True,
    )

    # submitted / resubmitted / approved / rejected / etc.
    action = db.Column(db.String(32), nullable=False)

    # farmer / admin
    actor_role = db.Column(db.String(16), nullable=False, default="farmer")
    actor_id = db.Column(db.String(36), nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # JSON stored as TEXT for portability
    changed_fields_json = db.Column(db.Text, nullable=True)
    before_json = db.Column(db.Text, nullable=True)
    after_json = db.Column(db.Text, nullable=True)

    notes = db.Column(db.Text, nullable=True)

    # -------------------------------------------------------------------------
    # Internal JSON helpers
    # -------------------------------------------------------------------------
    def _load_json_list(self, raw_value: Any) -> List[Dict[str, Any]]:
        """
        Safely decode a JSON array stored in a text column.

        Why this helper exists:
          Pyright sees SQLAlchemy model attributes as descriptor/column-backed
          values, so passing `self.changed_fields_json` directly into json.loads()
          can raise a type error at static-check time.

        This helper first normalizes the runtime value into a plain str.
        """
        if raw_value is None:
            return []

        if isinstance(raw_value, (bytes, bytearray)):
            try:
                raw_text = raw_value.decode("utf-8", errors="ignore").strip()
            except Exception:
                return []
        elif isinstance(raw_value, str):
            raw_text = raw_value.strip()
        else:
            # Avoid passing SQLAlchemy descriptor-like objects to json.loads().
            try:
                raw_text = str(raw_value).strip()
            except Exception:
                return []

        if not raw_text:
            return []

        try:
            parsed = json.loads(raw_text)
            if isinstance(parsed, list):
                return [row for row in parsed if isinstance(row, dict)]
            return []
        except Exception:
            return []

    def _load_json_dict(self, raw_value: Any) -> Dict[str, Any]:
        """
        Safely decode a JSON object stored in a text column.
        """
        if raw_value is None:
            return {}

        if isinstance(raw_value, (bytes, bytearray)):
            try:
                raw_text = raw_value.decode("utf-8", errors="ignore").strip()
            except Exception:
                return {}
        elif isinstance(raw_value, str):
            raw_text = raw_value.strip()
        else:
            try:
                raw_text = str(raw_value).strip()
            except Exception:
                return {}

        if not raw_text:
            return {}

        try:
            parsed = json.loads(raw_text)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}

    # -------------------------------------------------------------------------
    # Public setters / getters
    # -------------------------------------------------------------------------
    def set_changed_fields(self, rows: List[Dict[str, Any]]) -> None:
        self.changed_fields_json = json.dumps(rows, default=str)

    def get_changed_fields(self) -> List[Dict[str, Any]]:
        return self._load_json_list(self.changed_fields_json)

    def set_before(self, data: Dict[str, Any]) -> None:
        self.before_json = json.dumps(data, default=str)

    def get_before(self) -> Dict[str, Any]:
        return self._load_json_dict(self.before_json)

    def set_after(self, data: Dict[str, Any]) -> None:
        self.after_json = json.dumps(data, default=str)

    def get_after(self) -> Dict[str, Any]:
        return self._load_json_dict(self.after_json)