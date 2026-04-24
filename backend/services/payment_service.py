# ============================================================================
# backend/services/payment_service.py — Payment Helpers / Summary Service
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Canonical helper layer for reading/updating payment data from the real
#   `payments` table.
#
# WHY THIS FILE EXISTS:
#   The Order model does not store canonical payment fields like:
#     • payment_status
#     • payment_method
#     • paid_at
#
#   Those values must be derived from the payments table.
#
# USED BY:
#   • backend/routes/admin_orders.py
#   • order serializers / admin reports / dashboard helpers
#
# IMPORTANT DOMAIN RULE:
#   The physical payments.status column supports:
#     unpaid, paid, pending, failed, refunded
#
#   "partial" is NOT a stored DB status.
#   It is derived in summary responses when:
#     0 < total_paid < expected_total
# ============================================================================
from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

from sqlalchemy import desc, select

from backend.database.db import db
from backend.models.payment import PAYMENT_ALLOWED_STATUSES, Payment


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        text_value = str(value).strip()
    except Exception:
        return None
    return text_value or None


def _safe_uuid(value: Any) -> Optional[uuid.UUID]:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _safe_decimal(value: Any, default: Decimal = Decimal("0.00")) -> Decimal:
    if value is None or value == "":
        return default
    try:
        return Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return default


def _normalize_status(value: Any) -> str:
    raw = (_safe_str(value) or "unpaid").lower()
    return raw if raw in PAYMENT_ALLOWED_STATUSES else "unpaid"


def _ts_or_none(value: Any) -> Optional[str]:
    try:
        return value.isoformat() if value else None
    except Exception:
        return None


def _latest_payment_stmt(order_id: uuid.UUID, user_id: Optional[uuid.UUID] = None):
    stmt = select(Payment).where(Payment.order_id == order_id)
    if user_id is not None:
        stmt = stmt.where(Payment.user_id == user_id)
    return stmt.order_by(
        desc(Payment.updated_at),
        desc(Payment.created_at),
        desc(Payment.payment_id),
    ).limit(1)


def _all_payments_stmt(order_id: uuid.UUID, user_id: Optional[uuid.UUID] = None):
    stmt = select(Payment).where(Payment.order_id == order_id)
    if user_id is not None:
        stmt = stmt.where(Payment.user_id == user_id)
    return stmt.order_by(
        desc(Payment.updated_at),
        desc(Payment.created_at),
        desc(Payment.payment_id),
    )


# ----------------------------------------------------------------------------
# Read helpers
# ----------------------------------------------------------------------------
def get_latest_order_payment(order_id: Any, *, user_id: Any = None) -> Optional[Payment]:
    """
    Return the most recent payment row for an order.

    When user_id is supplied, this only reads rows for that payment scope.
    """
    order_uuid = _safe_uuid(order_id)
    scope_user_uuid = _safe_uuid(user_id)
    if order_uuid is None:
        return None

    try:
        return db.session.execute(_latest_payment_stmt(order_uuid, scope_user_uuid)).scalar_one_or_none()
    except Exception:
        return None


def get_order_payments(order_id: Any, *, user_id: Any = None) -> list[Payment]:
    """
    Return payment rows for an order, newest first.

    When user_id is supplied, this only returns rows for that payment scope.
    """
    order_uuid = _safe_uuid(order_id)
    scope_user_uuid = _safe_uuid(user_id)
    if order_uuid is None:
        return []

    try:
        return list(db.session.execute(_all_payments_stmt(order_uuid, scope_user_uuid)).scalars().all())
    except Exception:
        return []


def serialize_payment(payment: Optional[Payment]) -> Optional[dict[str, Any]]:
    """
    Stable serializer for a single payment row.

    Compatibility aliases included for order serializers:
      - reference_raw
      - proof_name
      - scope_user_id
    """
    if payment is None:
        return None

    proof_url = _safe_str(getattr(payment, "proof_url", None))
    proof_name = proof_url.rstrip("/").split("/")[-1] if proof_url else None
    reference = _safe_str(getattr(payment, "reference", None))
    user_id = getattr(payment, "user_id", None)

    return {
        "payment_id": int(getattr(payment, "payment_id", 0) or 0),
        "id": int(getattr(payment, "payment_id", 0) or 0),
        "order_id": str(getattr(payment, "order_id", "")),
        "amount": float(_safe_decimal(getattr(payment, "amount", 0))),
        "status": _safe_str(getattr(payment, "status", None)) or "unpaid",
        "method": _safe_str(getattr(payment, "method", None)),
        "reference": reference,
        "reference_raw": reference,
        "created_at": _ts_or_none(getattr(payment, "created_at", None)),
        "updated_at": _ts_or_none(getattr(payment, "updated_at", None)),
        "user_id": str(user_id) if user_id is not None else None,
        "scope_user_id": str(user_id) if user_id is not None else None,
        "proof_url": proof_url,
        "proof_name": proof_name,
        "proof_uploaded_at": _ts_or_none(getattr(payment, "proof_uploaded_at", None)),
        "has_proof": bool(proof_url),
    }


def serialize_latest_order_payment(order_id: Any, *, user_id: Any = None) -> Optional[dict[str, Any]]:
    """
    Serialized latest payment row for an order.
    """
    return serialize_payment(get_latest_order_payment(order_id, user_id=user_id))


def serialize_order_payments(order_id: Any, *, user_id: Any = None) -> list[dict[str, Any]]:
    """
    Serialized payment history for an order.

    When user_id is supplied, this only returns rows for that payment scope.
    """
    return [row for row in (serialize_payment(p) for p in get_order_payments(order_id, user_id=user_id)) if row]


# ----------------------------------------------------------------------------
# Derived summary
# ----------------------------------------------------------------------------
def build_order_payment_summary(
    order_id: Any,
    *,
    expected_total: Any = 0,
    user_id: Any = None,
) -> dict[str, Any]:
    """
    Derive a frontend/admin-friendly payment summary from payment rows.

    Compatibility fields returned for newer order serializers:
      - stored_status / derived_status
      - paid_total (alias of total_paid)
      - payments (serialized rows)

    Scope behavior:
      - user_id=None  -> whole-order payment history
      - user_id=<id>  -> matching scoped rows only
      - if scoped rows do not exist, we gracefully fall back to whole-order rows
        for summary purposes only. Direct `serialize_order_payments(..., user_id=...)`
        remains strict, which protects scoped proof visibility.
    """
    order_uuid = _safe_uuid(order_id)
    requested_scope_user_uuid = _safe_uuid(user_id)
    if order_uuid is None:
        empty_expected = float(_safe_decimal(expected_total))
        return {
            "order_id": None,
            "user_id": str(requested_scope_user_uuid) if requested_scope_user_uuid else None,
            "scope_user_id": str(requested_scope_user_uuid) if requested_scope_user_uuid else None,
            "expected_total": empty_expected,
            "total_paid": 0.0,
            "paid_total": 0.0,
            "total_recorded": 0.0,
            "payment_status": "unpaid",
            "stored_status": "unpaid",
            "derived_status": "unpaid",
            "payment_method": None,
            "payment_reference": None,
            "paid_at": None,
            "latest_payment": None,
            "latest_paid_payment": None,
            "proof_url": None,
            "proof_uploaded_at": None,
            "has_proof": False,
            "payments_count": 0,
            "payments": [],
            "used_scope_filter": False,
        }

    expected_amount = _safe_decimal(expected_total)

    scoped_rows: list[Payment] = []
    used_scope_filter = False
    if requested_scope_user_uuid is not None:
        scoped_rows = get_order_payments(order_uuid, user_id=requested_scope_user_uuid)
        if scoped_rows:
            used_scope_filter = True

    rows = scoped_rows if scoped_rows else get_order_payments(order_uuid)
    latest = rows[0] if rows else None

    total_recorded = Decimal("0.00")
    total_paid = Decimal("0.00")
    latest_paid_row: Optional[Payment] = None

    for row in rows:
        amt = _safe_decimal(getattr(row, "amount", 0))
        total_recorded += amt

        status = _normalize_status(getattr(row, "status", None))
        if status == "paid":
            total_paid += amt
            if latest_paid_row is None:
                latest_paid_row = row

    latest_status = _normalize_status(getattr(latest, "status", None)) if latest else "unpaid"
    stored_status = latest_status or "unpaid"

    if expected_amount > Decimal("0.00") and total_paid > Decimal("0.00") and total_paid < expected_amount:
        derived_status = "partial"
    elif total_paid > Decimal("0.00") and (expected_amount == Decimal("0.00") or total_paid >= expected_amount):
        derived_status = "paid"
    elif stored_status in {"pending", "failed", "refunded"}:
        derived_status = stored_status
    else:
        derived_status = stored_status or "unpaid"

    method_value = (
        _safe_str(getattr(latest, "method", None))
        or _safe_str(getattr(latest_paid_row, "method", None))
    )
    reference_value = (
        _safe_str(getattr(latest, "reference", None))
        or _safe_str(getattr(latest_paid_row, "reference", None))
    )

    paid_at_source = None
    if latest_paid_row is not None:
        paid_at_source = getattr(latest_paid_row, "updated_at", None) or getattr(latest_paid_row, "created_at", None)

    proof_url = (
        _safe_str(getattr(latest, "proof_url", None))
        or _safe_str(getattr(latest_paid_row, "proof_url", None))
    )
    proof_uploaded_at = (
        getattr(latest, "proof_uploaded_at", None)
        or getattr(latest_paid_row, "proof_uploaded_at", None)
    )

    serialized_rows = [row for row in (serialize_payment(p) for p in rows) if row]
    latest_payment_payload = serialize_payment(latest)
    latest_paid_payment_payload = serialize_payment(latest_paid_row)

    # If a scoped lookup had to fall back to whole-order rows, expose the summary
    # as order-level so caller logic does not mistake unrelated user_id values for
    # a valid farmer-scoped payment stream.
    if requested_scope_user_uuid is not None and not used_scope_filter:
        for row in serialized_rows:
            row["user_id"] = None
            row["scope_user_id"] = None
        if isinstance(latest_payment_payload, dict):
            latest_payment_payload["user_id"] = None
            latest_payment_payload["scope_user_id"] = None
        if isinstance(latest_paid_payment_payload, dict):
            latest_paid_payment_payload["user_id"] = None
            latest_paid_payment_payload["scope_user_id"] = None

    return {
        "order_id": str(order_uuid),
        "user_id": str(requested_scope_user_uuid) if requested_scope_user_uuid else None,
        "scope_user_id": str(requested_scope_user_uuid) if requested_scope_user_uuid else None,
        "expected_total": float(expected_amount),
        "total_paid": float(total_paid),
        "paid_total": float(total_paid),
        "total_recorded": float(total_recorded),
        "payment_status": derived_status,
        "stored_status": stored_status,
        "derived_status": derived_status,
        "payment_method": method_value,
        "payment_reference": reference_value,
        "paid_at": _ts_or_none(paid_at_source),
        "latest_payment": latest_payment_payload,
        "latest_paid_payment": latest_paid_payment_payload,
        "proof_url": proof_url,
        "proof_uploaded_at": _ts_or_none(proof_uploaded_at),
        "has_proof": bool(proof_url),
        "payments_count": len(rows),
        "payments": serialized_rows,
        "used_scope_filter": used_scope_filter,
    }


# ----------------------------------------------------------------------------
# Write helper
# ----------------------------------------------------------------------------
def upsert_order_payment(
    *,
    order_id: Any,
    amount: Any,
    status: Any,
    method: Any = None,
    reference: Any = None,
    user_id: Any = None,
    proof_url: Any = None,
    proof_uploaded_at: Any = None,
    commit: bool = False,
) -> Payment:
    """
    Create a new payment row or update the latest one for the same order when it
    still represents the same lifecycle entry.

    CURRENT STRATEGY:
      - If there is no payment row for the order -> create one
      - If the latest row exists -> update that latest row in place

    WHY:
      This keeps admin/manual corrections simple and matches the current codebase
      expectation used by admin order management.

    NOTE:
      If you later need immutable payment event history, change this strategy to
      "always insert new row" and let summary/report code consume the full trail.
    """
    order_uuid = _safe_uuid(order_id)
    if order_uuid is None:
        raise ValueError("Valid order_id is required")

    latest = get_latest_order_payment(order_uuid)

    normalized_status = _normalize_status(status)
    normalized_amount = _safe_decimal(amount)
    normalized_method = _safe_str(method)
    normalized_reference = _safe_str(reference)
    normalized_user_id = _safe_uuid(user_id)
    normalized_proof_url = _safe_str(proof_url)

    if latest is None:
        latest = Payment()
        latest.order_id = order_uuid

    latest.amount = normalized_amount
    latest.status = normalized_status
    latest.method = normalized_method
    latest.reference = normalized_reference
    latest.user_id = normalized_user_id

    if normalized_proof_url is not None:
        latest.proof_url = normalized_proof_url

    if proof_uploaded_at is not None:
        latest.proof_uploaded_at = proof_uploaded_at
    elif normalized_proof_url and getattr(latest, "proof_uploaded_at", None) is None:
        latest.proof_uploaded_at = datetime.utcnow()

    latest.updated_at = datetime.utcnow()

    db.session.add(latest)

    if commit:
        db.session.commit()
        db.session.refresh(latest)
    else:
        db.session.flush()

    return latest


# ----------------------------------------------------------------------------
# Backward-compatible aliases for older code
# ----------------------------------------------------------------------------
def get_latest_payment(order_id: Any, *, user_id: Any = None) -> Optional[Payment]:
    return get_latest_order_payment(order_id, user_id=user_id)


def get_payment_summary(order_id: Any, expected_total: Any = 0, *, user_id: Any = None) -> dict[str, Any]:
    return build_order_payment_summary(order_id, expected_total=expected_total, user_id=user_id)


def serialize_payment_summary(order_id: Any, expected_total: Any = 0, *, user_id: Any = None) -> dict[str, Any]:
    return build_order_payment_summary(order_id, expected_total=expected_total, user_id=user_id)
