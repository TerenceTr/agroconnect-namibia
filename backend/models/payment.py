# ============================================================================
# backend/models/payment.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Minimal, type-checker-friendly SQLAlchemy model for AgroConnect payments.
#
# WHY THIS VERSION:
#   ✅ Removes db.relationship / db.backref usage that your checker flags
#   ✅ Avoids direct float(...) / .isoformat() calls on ORM descriptors
#   ✅ Keeps the current database schema and status constraint intact
#   ✅ Keeps proof_url separate from the short payment reference
#
# CURRENT DATABASE SHAPE:
#   payments.payment_id           -> integer PK
#   payments.order_id             -> uuid NOT NULL
#   payments.amount               -> numeric(10,2) NOT NULL
#   payments.status               -> varchar(20) NOT NULL
#   payments.method               -> varchar(30) NULL
#   payments.reference            -> varchar(120) NULL
#   payments.created_at           -> timestamp NOT NULL default now()
#   payments.user_id              -> uuid NULL
#   payments.updated_at           -> timestamp NOT NULL default now()
#   payments.proof_url            -> text NULL
#   payments.proof_uploaded_at    -> timestamp NULL
# ============================================================================

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, Optional, cast

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, Numeric, String, Text, text
from sqlalchemy.dialects.postgresql import UUID

from backend.database.db import db


# -----------------------------------------------------------------------------
# Stable payment statuses allowed by the current database constraint
# -----------------------------------------------------------------------------
PAYMENT_STATUS_UNPAID = "unpaid"
PAYMENT_STATUS_PAID = "paid"
PAYMENT_STATUS_PENDING = "pending"
PAYMENT_STATUS_FAILED = "failed"
PAYMENT_STATUS_REFUNDED = "refunded"

PAYMENT_ALLOWED_STATUSES = {
    PAYMENT_STATUS_UNPAID,
    PAYMENT_STATUS_PAID,
    PAYMENT_STATUS_PENDING,
    PAYMENT_STATUS_FAILED,
    PAYMENT_STATUS_REFUNDED,
}


# -----------------------------------------------------------------------------
# Small value helpers
# -----------------------------------------------------------------------------
def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text_value = str(value).strip()
    return text_value if text_value else None


def _safe_decimal_str(value: Any, fallback: str = "0.00") -> str:
    try:
        if isinstance(value, Decimal):
            return format(value, "f")
        return format(Decimal(str(value)), "f")
    except Exception:
        return fallback


def _instance_attr(obj: Any, name: str) -> Any:
    """
    Read ORM-backed instance values through getattr so type checkers stop
    treating class descriptors as runtime values.
    """
    return getattr(obj, name, None)


def _instance_datetime_iso(obj: Any, name: str) -> Optional[str]:
    value = cast(Optional[datetime], _instance_attr(obj, name))
    return value.isoformat() if isinstance(value, datetime) else None


def _instance_decimal_float(obj: Any, name: str, fallback: float = 0.0) -> float:
    value = _instance_attr(obj, name)
    try:
        if value is None:
            return fallback
        if isinstance(value, Decimal):
            return float(value)
        return float(Decimal(str(value)))
    except Exception:
        return fallback


class Payment(db.Model):
    """
    Canonical payment row for AgroConnect.

    IMPORTANT:
      - reference stores only the short user-facing payment reference
      - proof_url stores the uploaded proof file path/url
      - user_id can be null for order-level payments or set for farmer-scoped
        payment rows in split-checkout flows
    """

    __tablename__ = "payments"

    __table_args__ = (
        CheckConstraint(
            "status IN ('unpaid', 'paid', 'pending', 'failed', 'refunded')",
            name="ck_payments_status",
        ),
        Index("ix_payments_order_id", "order_id"),
        Index("ix_payments_user_id", "user_id"),
        Index("ix_payments_order_user", "order_id", "user_id"),
    )

    # -------------------------------------------------------------------------
    # Primary key
    # -------------------------------------------------------------------------
    payment_id = db.Column(Integer, primary_key=True, autoincrement=True)

    # -------------------------------------------------------------------------
    # Core identifiers
    # -------------------------------------------------------------------------
    order_id = db.Column(
        UUID(as_uuid=True),
        ForeignKey("orders.order_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id = db.Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # -------------------------------------------------------------------------
    # Commercial fields
    # -------------------------------------------------------------------------
    amount = db.Column(Numeric(10, 2), nullable=False)
    status = db.Column(String(20), nullable=False, server_default=text("'unpaid'"))
    method = db.Column(String(30), nullable=True)
    reference = db.Column(String(120), nullable=True)

    # -------------------------------------------------------------------------
    # Proof-of-payment fields
    # -------------------------------------------------------------------------
    proof_url = db.Column(Text, nullable=True)
    proof_uploaded_at = db.Column(db.DateTime, nullable=True)

    # -------------------------------------------------------------------------
    # Audit timestamps
    # -------------------------------------------------------------------------
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=text("now()"),
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        server_default=text("now()"),
        onupdate=datetime.utcnow,
    )

    # -------------------------------------------------------------------------
    # Convenience flags
    # -------------------------------------------------------------------------
    @property
    def is_paid(self) -> bool:
        return (_safe_str(_instance_attr(self, "status")) or "").lower() == PAYMENT_STATUS_PAID

    @property
    def is_pending(self) -> bool:
        return (_safe_str(_instance_attr(self, "status")) or "").lower() == PAYMENT_STATUS_PENDING

    @property
    def is_unpaid(self) -> bool:
        return (_safe_str(_instance_attr(self, "status")) or "").lower() == PAYMENT_STATUS_UNPAID

    @property
    def has_proof(self) -> bool:
        return bool(_safe_str(_instance_attr(self, "proof_url")))

    @property
    def has_reference(self) -> bool:
        return bool(_safe_str(_instance_attr(self, "reference")))

    @property
    def method_key(self) -> Optional[str]:
        return (_safe_str(_instance_attr(self, "method")) or "").lower() or None

    # -------------------------------------------------------------------------
    # Normalization helpers
    # -------------------------------------------------------------------------
    def normalize_status(self) -> str:
        """
        Keep status inside the currently allowed DB-safe set.
        """
        normalized = (_safe_str(_instance_attr(self, "status")) or PAYMENT_STATUS_UNPAID).lower()
        if normalized not in PAYMENT_ALLOWED_STATUSES:
            normalized = PAYMENT_STATUS_UNPAID
        self.status = normalized
        return normalized

    def set_reference(self, reference: Optional[str]) -> None:
        """
        Keep only the short user-facing reference string.
        """
        normalized = _safe_str(reference)
        self.reference = normalized[:120] if normalized else None

    def mark_proof_uploaded(self, proof_url: Optional[str]) -> None:
        """
        Attach proof file path/url and stamp upload time.
        """
        normalized = _safe_str(proof_url)
        self.proof_url = normalized
        self.proof_uploaded_at = datetime.utcnow() if normalized else None
            # -------------------------------------------------------------------------
    # Serialization helpers
    # -------------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        """
        Frontend/service-friendly serializer.

        Uses helper readers so static analysis does not confuse instance values
        with SQLAlchemy Column descriptors.
        """
        payment_id_value = _instance_attr(self, "payment_id")
        order_id_value = _instance_attr(self, "order_id")
        user_id_value = _instance_attr(self, "user_id")
        status_value = _safe_str(_instance_attr(self, "status")) or PAYMENT_STATUS_UNPAID
        method_value = _safe_str(_instance_attr(self, "method"))
        reference_value = _safe_str(_instance_attr(self, "reference"))
        proof_url_value = _safe_str(_instance_attr(self, "proof_url"))

        return {
            "payment_id": payment_id_value,
            "id": payment_id_value,
            "order_id": str(order_id_value) if order_id_value else None,
            "user_id": str(user_id_value) if user_id_value else None,
            "amount": _instance_decimal_float(self, "amount", 0.0),
            "amount_raw": _safe_decimal_str(_instance_attr(self, "amount")),
            "status": status_value,
            "method": method_value,
            "reference": reference_value,
            "proof_url": proof_url_value,
            "proof_uploaded_at": _instance_datetime_iso(self, "proof_uploaded_at"),
            "created_at": _instance_datetime_iso(self, "created_at"),
            "updated_at": _instance_datetime_iso(self, "updated_at"),
            "is_paid": self.is_paid,
            "is_pending": self.is_pending,
            "is_unpaid": self.is_unpaid,
            "has_proof": self.has_proof,
            "has_reference": self.has_reference,
        }

    def __repr__(self) -> str:
        return (
            f"<Payment payment_id={_instance_attr(self, 'payment_id')} "
            f"order_id={_instance_attr(self, 'order_id')} "
            f"user_id={_instance_attr(self, 'user_id')} "
            f"status={_safe_str(_instance_attr(self, 'status'))!r} "
            f"amount={_safe_decimal_str(_instance_attr(self, 'amount'))}>"
        )


__all__ = [
    "Payment",
    "PAYMENT_STATUS_UNPAID",
    "PAYMENT_STATUS_PAID",
    "PAYMENT_STATUS_PENDING",
    "PAYMENT_STATUS_FAILED",
    "PAYMENT_STATUS_REFUNDED",
    "PAYMENT_ALLOWED_STATUSES",
]