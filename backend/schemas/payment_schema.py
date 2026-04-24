# ============================================================================
# backend/schemas/payment_schema.py — Payment serializer / DTO helpers
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Canonical JSON shape for Payment domain responses.
#
# IMPORTANT:
#   ✅ DB statuses are:
#        unpaid, paid, pending, failed, refunded
#   ✅ "partial" is derived in summary logic only
#   ✅ Supports legacy JSON references, but no longer depends on them
#   ✅ Derives proof_name from proof_url when proof_name is not stored explicitly
# ============================================================================

from __future__ import annotations

import json
import os
from datetime import datetime
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, Iterable, Optional, TYPE_CHECKING, TypedDict
from urllib.parse import unquote, urlparse

if TYPE_CHECKING:
    from backend.models.payment import Payment


# ----------------------------------------------------------------------------
# Allowed stored statuses from DB
# ----------------------------------------------------------------------------
PAYMENT_ALLOWED_STATUSES: frozenset[str] = frozenset(
    {"unpaid", "paid", "pending", "failed", "refunded"}
)


# ----------------------------------------------------------------------------
# Typed payload for parsed payment-reference values
# ----------------------------------------------------------------------------
class PaymentReferenceParts(TypedDict):
    reference: Optional[str]
    proof_url: Optional[str]
    proof_name: Optional[str]


# ----------------------------------------------------------------------------
# Small safe helpers
# ----------------------------------------------------------------------------
def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _to_decimal(value: Any, default: Optional[Decimal] = None) -> Optional[Decimal]:
    if value is None:
        return default
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return default


def _q2(value: Any) -> Decimal:
    d = _to_decimal(value, Decimal("0.00")) or Decimal("0.00")
    return d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _dt_iso(value: Any) -> Optional[str]:
    return value.isoformat() if isinstance(value, datetime) else None


def _proof_name_from_url(url: Any) -> Optional[str]:
    """
    Best-effort filename recovery from proof_url.

    This is important now that proof metadata is no longer packed into
    payments.reference JSON for new uploads.
    """
    s = _safe_str(url)
    if not s:
        return None

    try:
        path = urlparse(s).path or s
    except Exception:
        path = s

    name = os.path.basename(path.replace("\\", "/")).strip()
    name = unquote(name)

    if not name:
        return None

    # Uploaded names are stored like:
    #   <uuidhex>_<original_filename>
    # Strip the generated prefix when present so UI shows the real filename.
    if "_" in name:
        prefix, rest = name.split("_", 1)
        if len(prefix) >= 16 and rest:
            return rest

    return name


# ----------------------------------------------------------------------------
# Presentation helpers
# ----------------------------------------------------------------------------
def payment_badge(status: Optional[str]) -> dict[str, str]:
    s = (_safe_str(status) or "unpaid").lower()

    if s == "paid":
        return {"key": "paid", "label": "Paid", "tone": "success"}
    if s == "partial":
        return {"key": "partial", "label": "Partially Paid", "tone": "warning"}
    if s == "pending":
        return {"key": "pending", "label": "Pending", "tone": "info"}
    if s == "failed":
        return {"key": "failed", "label": "Failed", "tone": "danger"}
    if s == "refunded":
        return {"key": "refunded", "label": "Refunded", "tone": "neutral"}

    return {"key": "unpaid", "label": "Unpaid", "tone": "danger"}


# ----------------------------------------------------------------------------
# Legacy payment reference parser
# ----------------------------------------------------------------------------
def parse_payment_reference(raw: Optional[str]) -> PaymentReferenceParts:
    """
    Compatibility parser for old rows that may contain JSON in reference:
      {"reference":"...", "proof_url":"...", "proof_name":"..."}

    New rows should normally store a plain human reference only.
    """
    out: PaymentReferenceParts = {
        "reference": None,
        "proof_url": None,
        "proof_name": None,
    }

    s = _safe_str(raw)
    if not s:
        return out

    if s.startswith("{") and s.endswith("}"):
        try:
            data = json.loads(s)
            if isinstance(data, dict):
                out["reference"] = _safe_str(data.get("reference"))
                out["proof_url"] = _safe_str(data.get("proof_url"))
                out["proof_name"] = _safe_str(data.get("proof_name")) or _proof_name_from_url(
                    data.get("proof_url")
                )
                return out
        except Exception:
            pass

    out["reference"] = s
    return out


# ----------------------------------------------------------------------------
# Single payment serialization
# ----------------------------------------------------------------------------
def serialize_payment(payment: "Payment") -> dict[str, Any]:
    parsed_ref = parse_payment_reference(_safe_str(payment.reference))
    status = (_safe_str(payment.status) or "unpaid").lower()

    # Prefer dedicated column first.
    proof_url = _safe_str(payment.proof_url) or parsed_ref["proof_url"]
    proof_name = parsed_ref["proof_name"] or _proof_name_from_url(proof_url)

    return {
        "payment_id": int(payment.payment_id),
        "order_id": str(payment.order_id),
        "user_id": str(payment.user_id) if payment.user_id else None,
        "amount": str(_q2(payment.amount)),
        "amount_value": float(_q2(payment.amount)),
        "status": status,
        "status_badge": payment_badge(status),
        "method": _safe_str(payment.method),
        "reference": parsed_ref["reference"],
        "reference_raw": _safe_str(payment.reference),
        "proof_url": proof_url,
        "proof_name": proof_name,
        "proof_uploaded_at": _dt_iso(payment.proof_uploaded_at),
        "created_at": _dt_iso(payment.created_at),
        "updated_at": _dt_iso(payment.updated_at),
    }


# ----------------------------------------------------------------------------
# List serialization
# ----------------------------------------------------------------------------
def serialize_payment_list(payments: Iterable["Payment"]) -> list[dict[str, Any]]:
    return [serialize_payment(p) for p in payments]


# ----------------------------------------------------------------------------
# Summary serialization
# ----------------------------------------------------------------------------
def serialize_payment_summary(
    payments: Iterable["Payment"],
    *,
    expected_total: Any = None,
) -> dict[str, Any]:
    rows = list(payments)

    expected = _to_decimal(expected_total, None)
    paid_total = Decimal("0.00")

    for payment in rows:
        if (_safe_str(payment.status) or "").lower() == "paid":
            paid_total += _q2(payment.amount)

    paid_total = _q2(paid_total)
    latest = rows[0] if rows else None

    stored_status = (_safe_str(latest.status) if latest is not None else None) or "unpaid"
    derived_status = stored_status

    if expected is not None and expected > Decimal("0"):
        if paid_total >= expected:
            derived_status = "paid"
        elif paid_total > Decimal("0"):
            derived_status = "partial"
        elif stored_status == "pending":
            derived_status = "pending"
        else:
            derived_status = "unpaid"

    latest_payload = serialize_payment(latest) if latest is not None else None

    return {
        "stored_status": stored_status,
        "derived_status": derived_status,
        "expected_total": str(_q2(expected)) if expected is not None else None,
        "paid_total": str(paid_total),
        "due_total": str(_q2((expected or Decimal("0.00")) - paid_total))
        if expected is not None
        else None,
        "payment_count": len(rows),
        "latest_payment": latest_payload,
        "payments": serialize_payment_list(rows),
    }