# ============================================================================
# backend/routes/orders.py — Orders API (Split-checkout + Scoped Farmer View)
# ----------------------------------------------------------------------------
# FILE ROLE (brief):
#   Orders endpoints used by Customer + Farmer dashboards:
#   • GET  /api/orders
#   • GET  /api/orders/me
#   • GET  /api/orders/my (alias)
#   • GET  /api/orders/<order_id>
#   • GET  /api/orders/farmer/<farmer_id>
#   • GET  /api/orders/farmer/me (alias)
#   • GET  /api/orders/farmer/my (alias)
#   • GET  /api/orders/farmer/<farmer_id>/top-products
#   • GET  /api/orders/farmer/me/top-products (alias)
#   • PUT  /api/orders/<order_id>/farmer-status
#   • POST /api/orders  (checkout: split into 1 order per farmer)
#   • POST /api/orders/<order_id>/payment-proof
#   • POST /api/orders/<order_id>/payment_proof (alias)
#
# THIS VERSION:
#   ✅ Uses the canonical Payment model/service layer
#   ✅ Matches the real DB schema:
#        - orders.order_total
#        - order_items.quantity numeric(12,3)
#        - order_items.delivered_quantity numeric(12,3)
#        - payments.payment_id integer PK
#   ✅ Keeps frontend-friendly response aliases
#   ✅ Keeps multipart payment proof upload support
#   ✅ Keeps auth-scoped farmer endpoints
#   ✅ Keeps rollback-safe farmer top products
#   ✅ Avoids raw-SQL payment scattering in routes
#
# MULTI-FARMER / SHARED ORDER FIX:
#   ✅ When a farmer views a shared order, the payload is scoped to the
#      farmer-owned slice:
#        - items -> only that farmer's items
#        - order_total / total / total_amount -> farmer subtotal
#        - delivery_status -> farmer-scoped derived delivery state
#        - payment fields -> farmer-scoped via payments.user_id where available
#   ✅ Still preserves customer/header context:
#        - customer_order_total
#        - delivery address / customer location
#        - order reference / id
#
# BUYER / STATUS UX FIX:
#   ✅ Includes buyer/customer details in payload:
#        - buyer_name / customer_name
#        - buyer_email / customer_email
#        - buyer_phone / customer_phone
#        - buyer_location / customer_location
#        - buyer_address / customer_address
#   ✅ Farmer-scoped view marks status as "completed" when farmer payment
#      visibility is confirmed as "paid" (unless order is cancelled)
#
# CUSTOMER CHECKOUT FLOW FIX:
#   ✅ Initial checkout is now an ORDER REQUEST, not final payment
#   ✅ Customer cannot upload proof during initial checkout
#   ✅ Farmer later sets delivery fee
#   ✅ VAT is exposed automatically as 15% of (products + delivery fee)
#   ✅ Final customer-facing amount becomes:
#        grand_total = products_subtotal + delivery_fee + vat_amount
#   ✅ EFT proof upload is blocked until:
#        - delivery fee is ready
#        - checkout is payment-ready
#        - payment method is EFT / bank transfer
#   ✅ Cash on delivery does not require proof upload
#   ✅ EFT delivery progression is blocked until payment is confirmed
#   ✅ Order payload now includes:
#        - products_subtotal
#        - delivery_fee
#        - delivery_fee_status
#        - vat_rate
#        - vat_amount
#        - grand_total
#        - checkout_flow_active
#        - checkout_ready
#        - checkout_stage
#        - bank_details
#
# FARMER DELIVERY / PAYMENT PROOF / QUOTE FIX:
#   ✅ Farmer can change their scoped delivery status even on shared orders
#   ✅ Farmer can set delivery fee on exclusive/split orders
#   ✅ Farmer can mark order ready for payment
#   ✅ EFT-ready state requires complete bank details
#   ✅ Customer is notified when ready for payment
#   ✅ Farmer is notified on new order request
#   ✅ Farmer is notified when customer uploads EFT proof
#   ✅ Marking an item as delivered/completed can auto-fill delivered quantity
#      when the frontend does not send it explicitly
#   ✅ Farmer view never leaks another farmer's proof-of-payment attachment
#   ✅ Customer can upload proof of payment after checkout on an existing order
#      through /api/orders/<id>/payment-proof
#   ✅ For multi-farmer orders, payment proof upload is split by farmer scope
#      so each farmer only sees their own proof
#
# PAYMENT REFERENCE STORAGE FIX:
#   ✅ payments.reference stores only the short human reference string
#   ✅ proof_url is stored in the dedicated payments.proof_url column
#   ✅ prevents varchar(120) overflow during proof upload commit
#
# SERVER-PERSISTED NOTIFICATIONS UPDATE:
#   ✅ notify_user() may now receive metadata for durable bell notifications
#   ✅ New order notifications can be deduped with event_key
#   ✅ Proof upload notifications can carry proof metadata in data payload
#   ✅ Ready-for-payment notifications can carry checkout totals in data payload
#
# OPTIONAL DEPENDENCIES:
#   This file will gracefully degrade if these optional modules are not yet wired:
#   • backend.models.farmer_payment_profile
#   • backend.services.notifications
# ============================================================================

from __future__ import annotations

import json
import os
from datetime import date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from typing import Any, Dict, List, Optional, Set, Tuple, TypedDict
from uuid import UUID, uuid4

from flask.blueprints import Blueprint
from flask.globals import current_app, request
from flask.json import jsonify
from sqlalchemy import String as SAString
from sqlalchemy import cast as sa_cast
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.types import Numeric
from werkzeug.utils import secure_filename

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, User
from backend.services.payment_service import (
    build_order_payment_summary,
    serialize_order_payments,
    upsert_order_payment,
)
from backend.utils.require_auth import require_access_token

try:
    from backend.models.farmer_payment_profile import FarmerPaymentProfile
except Exception:  # pragma: no cover
    FarmerPaymentProfile = None  # type: ignore[assignment]

try:
    from backend.services.notifications import notify_user as _notify_user_service
except Exception:  # pragma: no cover
    _notify_user_service = None

orders_bp = Blueprint("orders", __name__)

_DEC2 = Decimal("0.01")
_DEC3 = Decimal("0.001")
_VAT_RATE = Decimal("0.15")
_ALLOWED_PROOF_EXTS = {"png", "jpg", "jpeg", "webp", "pdf"}
_ALLOWED_ORDER_STATUSES = {"pending", "completed", "cancelled"}
_ALLOWED_PAYMENT_STATUSES = {"unpaid", "paid", "pending", "failed", "refunded"}


def _vat_rate_decimal() -> Decimal:
    try:
        raw_percent = Decimal(str(current_app.config.get("VAT_PERCENT", "15")))
    except Exception:
        raw_percent = Decimal("15")
    if raw_percent < Decimal("0"):
        raw_percent = Decimal("0")
    return (raw_percent / Decimal("100")).quantize(Decimal("0.0001"))


def _checkout_setting_int(key: str, default: int, *, min_value: int, max_value: int) -> int:
    try:
        value = int(current_app.config.get(key, default))
    except Exception:
        value = default
    return max(min_value, min(max_value, value))


def _checkout_setting_bool(key: str, default: bool) -> bool:
    try:
        raw = current_app.config.get(key, default)
    except Exception:
        return default
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}


def _payment_method_is_codish(value: Any) -> bool:
    normalized = safeStr(value).lower()
    return any(part in normalized for part in ("cash", "cod", "delivery"))


def _default_checkout_payment_method() -> str:
    if _checkout_setting_bool("EFT_ENABLED", True):
        return "eft"
    if _checkout_setting_bool("CASH_ON_DELIVERY_ENABLED", False):
        return "cash_on_delivery"
    return "eft"


def _write_operations_blocked_message() -> Optional[str]:
    if _checkout_setting_bool("MAINTENANCE_MODE", False):
        return safeStr(
            current_app.config.get("MAINTENANCE_MESSAGE"),
            "Checkout is temporarily unavailable while the platform is in maintenance mode.",
        )
    if _checkout_setting_bool("READ_ONLY_MODE", False):
        return "Checkout is temporarily unavailable because the marketplace is in read-only mode."
    return None


def _validate_checkout_payment_method(payment_method: str) -> Optional[str]:
    if _payment_method_is_eftish(payment_method):
        if not _checkout_setting_bool("EFT_ENABLED", True):
            return "EFT / bank transfer is disabled in system settings."
        return None
    if _payment_method_is_codish(payment_method):
        if not _checkout_setting_bool("CASH_ON_DELIVERY_ENABLED", False):
            return "Cash on delivery is disabled in system settings."
        return None
    if _checkout_setting_bool("EFT_ENABLED", True):
        return None
    if _checkout_setting_bool("CASH_ON_DELIVERY_ENABLED", False):
        return None
    return "No checkout payment methods are enabled in system settings."


_READY_DELIVERY_FEE_STATUSES = {
    "quoted",
    "ready_for_payment",
    "awaiting_customer_payment",
    "checkout_ready",
    "customer_notified",
    "finalized",
    "set",
}


class PaymentReferenceParts(TypedDict):
    reference: Optional[str]
    proof_url: Optional[str]
    proof_name: Optional[str]


def token_required(fn):
    @wraps(fn)
    @require_access_token
    def wrapper(*args, **kwargs):
        user = getattr(request, "current_user", None)
        if not isinstance(user, User):
            return jsonify({"ok": False, "message": "Unauthorized"}), 401
        return fn(user, *args, **kwargs)

    return wrapper


def utcnow() -> datetime:
    return datetime.utcnow()


def _safe_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def safeStr(v: Any, fallback: str = "") -> str:
    return _safe_str(v) or fallback


def _as_uuid(v: Any) -> Optional[UUID]:
    if v is None:
        return None
    if isinstance(v, UUID):
        return v
    s = _safe_str(v)
    if not s:
        return None
    try:
        return UUID(s)
    except Exception:
        return None


def _to_decimal(v: Any, default: Optional[Decimal] = None) -> Optional[Decimal]:
    if v is None:
        return default
    try:
        if isinstance(v, Decimal):
            return v
        return Decimal(str(v))
    except (InvalidOperation, ValueError, TypeError):
        return default


def _q2(v: Optional[Decimal]) -> Decimal:
    base = v if isinstance(v, Decimal) else Decimal("0")
    return base.quantize(_DEC2)


def _q3(v: Optional[Decimal]) -> Decimal:
    base = v if isinstance(v, Decimal) else Decimal("0")
    return base.quantize(_DEC3)


def _dec2_float(v: Optional[Decimal]) -> float:
    return float(_q2(v))


def _dec3_float(v: Optional[Decimal]) -> float:
    return float(_q3(v))


def _dec_str(v: Optional[Decimal]) -> str:
    return str(_q2(v))


def _dt_iso(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return _safe_str(v)


def _parse_datetimeish(v: Any) -> Optional[datetime]:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v
    if isinstance(v, date):
        return datetime.combine(v, datetime.min.time())
    s = _safe_str(v)
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        pass
    try:
        if len(s) >= 10:
            return datetime.fromisoformat(s[:10] + "T00:00:00")
    except Exception:
        pass
    return None


def _is_admin(user: User) -> bool:
    raw_role = getattr(user, "role", None)
    role_name = _safe_str(getattr(user, "role_name", None) or getattr(user, "roleName", None))
    try:
        if raw_role is not None and int(raw_role) == int(ROLE_ADMIN):
            return True
    except Exception:
        pass
    return (role_name or _safe_str(raw_role) or "").lower() == "admin"


def _user_id(user: User) -> Optional[UUID]:
    return _as_uuid(getattr(user, "id", None) or getattr(user, "user_id", None))


def _set_if_has(obj: Any, attr: str, value: Any) -> None:
    if hasattr(obj, attr):
        setattr(obj, attr, value)


def _request_is_multipart() -> bool:
    ctype = (_safe_str(getattr(request, "content_type", None)) or "").lower()
    return "multipart/form-data" in ctype


def _read_form_as_dict() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in request.form.keys():
        out[key] = request.form.get(key)
    return out


def _coerce_items(raw: Any) -> List[Dict[str, Any]]:
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, str):
        s = raw.strip()
        if not s:
            return []
        try:
            parsed = json.loads(s)
            if isinstance(parsed, list):
                return [x for x in parsed if isinstance(x, dict)]
        except Exception:
            return []
    return []


def _normalize_public_path(path: Optional[str]) -> Optional[str]:
    s = _safe_str(path)
    if not s:
        return None
    if s.startswith("http://") or s.startswith("https://"):
        return s
    if s.startswith("/api/"):
        return s
    if s.startswith("/uploads/"):
        return f"/api{s}"
    if s.startswith("uploads/"):
        return f"/api/{s}"
    return f"/{s.lstrip('/')}"


def _is_truthy(v: Any) -> bool:
    s = (_safe_str(v) or "").lower()
    return s in {"1", "true", "yes", "y", "on"}


def _to_int(v: Any, default: int) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _parse_days_all_time(default_days: int = 90) -> Tuple[int, bool]:
    all_time = _is_truthy(request.args.get("all_time")) or _is_truthy(request.args.get("allTime"))
    days_raw = request.args.get("days", str(default_days))
    days = _to_int(days_raw, default_days)
    days = max(1, min(days, 3650))
    return days, all_time


def _normalize_order_status(v: Any) -> Optional[str]:
    s = (_safe_str(v) or "").lower()
    if not s:
        return None
    if s in {"completed", "delivered"}:
        return "completed"
    if s in {"cancelled", "canceled"}:
        return "cancelled"
    if s == "pending":
        return "pending"
    return None


def _normalize_payment_status_for_storage(v: Any) -> str:
    s = (_safe_str(v) or "unpaid").lower()
    if s == "partial":
        return "pending"
    return s if s in _ALLOWED_PAYMENT_STATUSES else "unpaid"


def _normalize_delivery_fee_status(value: Any) -> Optional[str]:
    s = (_safe_str(value) or "").strip().lower()
    return s or None


def _checkout_flow_active_from_status(value: Any) -> bool:
    return _normalize_delivery_fee_status(value) is not None


def _checkout_ready_from_status(value: Any) -> bool:
    normalized = _normalize_delivery_fee_status(value)
    if normalized is None:
        return True
    return normalized in _READY_DELIVERY_FEE_STATUSES


def _payment_method_is_eftish(value: Any) -> bool:
    normalized = (_safe_str(value) or "").lower()
    return any(part in normalized for part in ("eft", "bank", "transfer", "wire"))


def _normalized_checkout_payment_method(value: Any, fallback: Optional[str] = None) -> str:
    if _payment_method_is_eftish(value):
        return "eft"
    if _payment_method_is_codish(value):
        return "cash_on_delivery"
    fallback_value = _safe_str(fallback)
    if _payment_method_is_eftish(fallback_value):
        return "eft"
    if _payment_method_is_codish(fallback_value):
        return "cash_on_delivery"
    return _safe_str(value) or fallback_value or _default_checkout_payment_method()


def _payment_requires_pre_delivery_clearance(method: Any) -> bool:
    return _payment_method_is_eftish(method)


def _payment_submission_exists(reference_value: Any, proof_url: Any) -> bool:
    parsed = _parse_payment_reference(_safe_str(reference_value))
    return bool(
        parsed.get("reference")
        or parsed.get("proof_url")
        or _normalize_public_path(_safe_str(proof_url))
        or _safe_str(reference_value)
    )


def _delivery_status_requests_dispatch(*values: Any) -> bool:
    dispatch_like = {
        "ready",
        "ready_for_delivery",
        "in_transit",
        "out_for_delivery",
        "delivered",
        "completed",
    }
    for raw in values:
        normalized = (_safe_str(raw) or "").lower()
        if normalized in dispatch_like:
            return True
    return False


def _serialize_bank_details(
    *,
    bank_name: Any = None,
    account_name: Any = None,
    account_number: Any = None,
    branch_code: Any = None,
    payment_instructions: Any = None,
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "bank_name": _safe_str(bank_name),
        "account_name": _safe_str(account_name),
        "account_number": _safe_str(account_number),
        "branch_code": _safe_str(branch_code),
        "payment_instructions": _safe_str(payment_instructions),
    }
    payload["is_complete"] = bool(
        payload["bank_name"] and payload["account_name"] and payload["account_number"]
    )
    return payload


def _item_line_total_decimal(item: OrderItem) -> Decimal:
    explicit = _to_decimal(getattr(item, "line_total", None), None)
    if explicit is not None:
        return _q2(explicit)
    qty = _to_decimal(getattr(item, "quantity", None), Decimal("0")) or Decimal("0")
    unit_price = _to_decimal(getattr(item, "unit_price", None), Decimal("0")) or Decimal("0")
    return _q2(qty * unit_price)


def _items_products_subtotal(items: List[OrderItem]) -> Decimal:
    return _q2(sum((_item_line_total_decimal(item) for item in items), Decimal("0")))


def _build_checkout_financials(
    *,
    products_subtotal: Any,
    delivery_fee: Any,
    delivery_fee_status: Any,
    payment_status: Any,
    payment_method: Any = None,
    bank_details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    subtotal = _q2(_to_decimal(products_subtotal, Decimal("0")) or Decimal("0"))
    delivery = _q2(_to_decimal(delivery_fee, Decimal("0")) or Decimal("0"))
    vat_rate = _vat_rate_decimal()
    vat_amount = _q2((subtotal + delivery) * vat_rate)
    grand_total = _q2(subtotal + delivery + vat_amount)

    raw_delivery_status = _normalize_delivery_fee_status(delivery_fee_status)
    flow_active = _checkout_flow_active_from_status(raw_delivery_status)
    checkout_ready = _checkout_ready_from_status(raw_delivery_status) if flow_active else True

    normalized_payment = (_safe_str(payment_status) or "unpaid").lower()
    normalized_method = _normalized_checkout_payment_method(payment_method)
    is_cod = _payment_method_is_codish(normalized_method)

    if normalized_payment == "paid":
        checkout_stage = "cash_received" if is_cod else "payment_verified"
    elif normalized_payment in {"pending", "partial"}:
        checkout_stage = "payment_submitted"
    elif flow_active and checkout_ready:
        checkout_stage = "awaiting_cash_delivery" if is_cod else "awaiting_customer_payment"
    elif flow_active:
        checkout_stage = "awaiting_farmer_quote"
    else:
        checkout_stage = "legacy"

    details = bank_details if isinstance(bank_details, dict) else _serialize_bank_details()

    return {
        "products_subtotal": subtotal,
        "delivery_fee": delivery,
        "vat_rate": vat_rate,
        "vat_amount": vat_amount,
        "grand_total": grand_total,
        "delivery_fee_status": raw_delivery_status,
        "checkout_flow_active": flow_active,
        "checkout_ready": checkout_ready,
        "checkout_stage": checkout_stage,
        "payment_method": normalized_method,
        "bank_details": details,
    }


def _get_farmer_payment_profile(farmer_id: Optional[UUID]):
    if FarmerPaymentProfile is None:
        return None
    fid = _as_uuid(farmer_id)
    if fid is None:
        return None
    try:
        return (
            db.session.query(FarmerPaymentProfile)
            .filter(FarmerPaymentProfile.farmer_id == fid)
            .one_or_none()
        )
    except Exception:
        db.session.rollback()
        return None


def _extract_bank_details(order: Order, farmer_id: Optional[UUID] = None) -> Dict[str, Any]:
    direct = _serialize_bank_details(
        bank_name=getattr(order, "bank_name", None),
        account_name=getattr(order, "account_name", None)
        or getattr(order, "bank_account_name", None),
        account_number=getattr(order, "account_number", None)
        or getattr(order, "bank_account_number", None),
        branch_code=getattr(order, "branch_code", None)
        or getattr(order, "bank_branch_code", None),
        payment_instructions=getattr(order, "payment_instructions", None),
    )
    if direct.get("is_complete"):
        return direct
    effective_farmer_id = _as_uuid(farmer_id) or _infer_single_farmer_owner(order)
    if effective_farmer_id is None:
        return direct
    profile = _get_farmer_payment_profile(effective_farmer_id)
    if profile is None:
        return direct
    if not bool(getattr(profile, "is_active", True)):
        return direct
    return _serialize_bank_details(
        bank_name=getattr(profile, "bank_name", None),
        account_name=getattr(profile, "account_name", None),
        account_number=getattr(profile, "account_number", None),
        branch_code=getattr(profile, "branch_code", None),
        payment_instructions=getattr(profile, "payment_instructions", None),
    )


def _latest_scope_payment_fields(order_id: UUID, scope_user_id: UUID) -> Dict[str, Optional[str]]:
    summary = build_order_payment_summary(
        order_id,
        expected_total=Decimal("0.00"),
        user_id=scope_user_id,
    )
    latest = summary.get("latest_payment") if isinstance(summary, dict) else None
    latest = latest if isinstance(latest, dict) else {}
    return {
        "stored_status": (_safe_str(summary.get("stored_status")) if isinstance(summary, dict) else None) or "unpaid",
        "method": _safe_str(latest.get("method")),
        "reference": _safe_str(latest.get("reference")),
        "reference_raw": _safe_str(latest.get("reference_raw")),
        "proof_url": _normalize_public_path(_safe_str(latest.get("proof_url"))),
    }


def _notify_user_best_effort(user_id: Optional[UUID], subject: str, message: str, **kwargs: Any) -> None:
    uid = _as_uuid(user_id)
    if uid is None:
        return
    if _notify_user_service is None:
        current_app.logger.info(
            "Notification service unavailable. subject=%s user_id=%s message=%s",
            subject,
            uid,
            message,
        )
        return
    try:
        _notify_user_service(uid, subject, message, **kwargs)
    except Exception:
        current_app.logger.warning(
            "Notification failed for user_id=%s subject=%s",
            uid,
            subject,
        )


def _save_payment_proof_from_request() -> Optional[Dict[str, Any]]:
    if not _request_is_multipart():
        return None
    file = request.files.get("payment_proof") or request.files.get("proof_file") or request.files.get("proof")
    if file is None:
        return None
    original_name = _safe_str(getattr(file, "filename", None))
    if not original_name:
        return None
    safe_name = secure_filename(original_name)
    if not safe_name:
        raise ValueError("Invalid payment proof filename")
    ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
    if ext not in _ALLOWED_PROOF_EXTS:
        raise ValueError("Unsupported payment proof file type. Allowed: png, jpg, jpeg, webp, pdf")
    max_mb = int(current_app.config.get("MAX_PAYMENT_PROOF_MB", 8))
    max_bytes = max_mb * 1024 * 1024
    try:
        stream = file.stream
        stream.seek(0, os.SEEK_END)
        size = int(stream.tell())
        stream.seek(0)
    except Exception:
        size = 0
    if size > max_bytes:
        raise ValueError(f"Payment proof is too large. Max allowed size is {max_mb} MB")
    upload_root = _safe_str(current_app.config.get("UPLOAD_FOLDER")) or os.path.join(os.getcwd(), "uploads")
    proofs_dir = os.path.join(upload_root, "payment_proofs")
    os.makedirs(proofs_dir, exist_ok=True)
    new_name = f"{uuid4().hex}_{safe_name}"
    abs_path = os.path.join(proofs_dir, new_name)
    file.save(abs_path)
    return {"url": f"/api/uploads/payment_proofs/{new_name}", "name": original_name, "size": size}


def _read_checkout_payload() -> Dict[str, Any]:
    if _request_is_multipart():
        data = _read_form_as_dict()
        data["items"] = _coerce_items(data.get("items"))
        proof = _save_payment_proof_from_request()
        if proof:
            data["_payment_proof_meta"] = proof
        return data
    raw = request.get_json(silent=True)
    if isinstance(raw, dict):
        return raw
    return {}


def _order_pk_col():
    return getattr(Order, "order_id", None) or getattr(Order, "id", None)


def _order_date_col():
    return getattr(Order, "order_date", None) or getattr(Order, "created_at", None)


def _order_status_col_name() -> str:
    if hasattr(Order, "status"):
        return "status"
    if hasattr(Order, "order_status"):
        return "order_status"
    return "status"


def _order_total_col_name() -> str:
    if hasattr(Order, "order_total"):
        return "order_total"
    if hasattr(Order, "total_amount"):
        return "total_amount"
    if hasattr(Order, "total"):
        return "total"
    if hasattr(Order, "grand_total"):
        return "grand_total"
    return "order_total"


def _product_pk_col():
    return getattr(Product, "product_id", None) or getattr(Product, "id", None)


def _product_name_col():
    return getattr(Product, "product_name", None) or getattr(Product, "name", None)


def _product_owner_col():
    return getattr(Product, "user_id", None) or getattr(Product, "farmer_id", None)


def _line_total_expr():
    if hasattr(OrderItem, "line_total"):
        return sa_cast(getattr(OrderItem, "line_total"), Numeric())
    qty_col = getattr(OrderItem, "quantity", None)
    price_col = getattr(OrderItem, "unit_price", None)
    if qty_col is not None and price_col is not None:
        return sa_cast(qty_col, Numeric()) * sa_cast(price_col, Numeric())
    return sa_cast(0, Numeric())


def _order_uuid(order: Order) -> Optional[UUID]:
    return _as_uuid(getattr(order, "order_id", None) or getattr(order, "id", None))


def _order_buyer_uuid(order: Order) -> Optional[UUID]:
    return _as_uuid(getattr(order, "buyer_id", None) or getattr(order, "user_id", None))


def _order_item_uuid(item: OrderItem) -> Optional[UUID]:
    return _as_uuid(getattr(item, "order_item_id", None) or getattr(item, "id", None))


def _get_order_items(order: Order) -> List[OrderItem]:
    try:
        items = list(getattr(order, "items", []) or [])
        if items:
            return items
    except Exception:
        pass
    oid = _order_uuid(order)
    if not oid:
        return []
    q = db.session.query(OrderItem).filter(OrderItem.order_id == oid)
    if hasattr(OrderItem, "created_at"):
        q = q.order_by(OrderItem.created_at.asc())
    return q.all()


def _get_product(item: OrderItem) -> Optional[Product]:
    try:
        p = getattr(item, "product", None)
        if p is not None:
            return p
    except Exception:
        pass
    pid = _as_uuid(getattr(item, "product_id", None))
    if not pid:
        return None
    return db.session.get(Product, pid)


def _get_buyer_user(order: Order) -> Optional[User]:
    try:
        buyer_rel = getattr(order, "buyer", None)
        if isinstance(buyer_rel, User):
            return buyer_rel
    except Exception:
        pass
    try:
        user_rel = getattr(order, "user", None)
        if isinstance(user_rel, User):
            return user_rel
    except Exception:
        pass
    buyer_id = _order_buyer_uuid(order)
    if buyer_id is None:
        return None
    return db.session.get(User, buyer_id)


def _product_owner_uuid(product: Product) -> Optional[UUID]:
    return _as_uuid(getattr(product, "user_id", None) or getattr(product, "farmer_id", None))


def _product_owned_by(product: Product, farmer_id: UUID) -> bool:
    return _product_owner_uuid(product) == farmer_id


def _order_has_farmer_items(order: Order, farmer_id: UUID) -> bool:
    for item in _get_order_items(order):
        p = _get_product(item)
        if p is not None and _product_owned_by(p, farmer_id):
            return True
    return False


def _order_is_exclusive_for_farmer(order: Order, farmer_id: UUID) -> bool:
    items = _get_order_items(order)
    if not items:
        return False
    for item in items:
        p = _get_product(item)
        if p is None or not _product_owned_by(p, farmer_id):
            return False
    return True


def _get_farmer_items(order: Order, farmer_id: UUID) -> List[OrderItem]:
    out: List[OrderItem] = []
    for item in _get_order_items(order):
        product = _get_product(item)
        if product is not None and _product_owned_by(product, farmer_id):
            out.append(item)
    return out


def _farmer_subtotal(order: Order, farmer_id: UUID) -> Decimal:
    total = Decimal("0")
    for item in _get_farmer_items(order, farmer_id):
        line_total = _to_decimal(getattr(item, "line_total", None), None)
        if line_total is None:
            qty = _to_decimal(getattr(item, "quantity", None), Decimal("0")) or Decimal("0")
            price = _to_decimal(getattr(item, "unit_price", None), Decimal("0")) or Decimal("0")
            line_total = qty * price
        total += line_total
    return _q2(total)


def _owned_product_ids_for_farmer(farmer_id: UUID) -> Set[UUID]:
    owner_col = _product_owner_col()
    pk_col = _product_pk_col()
    if owner_col is None or pk_col is None:
        return set()
    rows = db.session.query(pk_col).filter(owner_col == farmer_id).all()
    out: Set[UUID] = set()
    for row in rows:
        pid = row[0] if isinstance(row, (tuple, list)) else row
        pu = _as_uuid(pid)
        if pu:
            out.add(pu)
    return out


def _infer_single_farmer_owner(order: Order) -> Optional[UUID]:
    owners: Set[UUID] = set()
    for item in _get_order_items(order):
        product = _get_product(item)
        if product is None:
            continue
        owner = _product_owner_uuid(product)
        if owner is not None:
            owners.add(owner)
    if len(owners) == 1:
        return next(iter(owners))
    return None


def _derive_farmer_delivery_summary(order: Order, farmer_id: UUID) -> Dict[str, Any]:
    scoped_items = _get_farmer_items(order, farmer_id)
    if not scoped_items:
        return {
            "delivery_status": "pending",
            "expected_delivery_date": _dt_iso(getattr(order, "expected_delivery_date", None)),
            "delivered_at": None,
            "ordered_quantity_total": 0.0,
            "delivered_quantity_total": 0.0,
            "item_count": 0,
        }
    ordered_total = Decimal("0")
    delivered_total = Decimal("0")
    statuses: List[str] = []
    delivered_ats: List[datetime] = []
    expected_dates: List[datetime] = []
    for item in scoped_items:
        qty = _to_decimal(getattr(item, "quantity", None), Decimal("0")) or Decimal("0")
        delivered_qty = _to_decimal(
            getattr(item, "delivered_quantity", None) or getattr(item, "delivered_qty", None),
            Decimal("0"),
        ) or Decimal("0")
        ordered_total += qty
        delivered_total += delivered_qty
        status = (
            _safe_str(
                getattr(item, "delivery_status", None)
                or getattr(item, "item_delivery_status", None)
                or getattr(item, "fulfillment_status", None)
            )
            or "pending"
        ).lower()
        statuses.append(status)
        delivered_at = getattr(item, "delivered_at", None)
        if isinstance(delivered_at, datetime):
            delivered_ats.append(delivered_at)
        expected_dt = _parse_datetimeish(
            getattr(item, "expected_delivery_date", None)
            or getattr(item, "item_expected_delivery_date", None)
        )
        if isinstance(expected_dt, datetime):
            expected_dates.append(expected_dt)
    all_cancelled = bool(statuses) and all(s == "cancelled" for s in statuses)
    all_delivered = bool(statuses) and all(s in {"delivered", "completed"} for s in statuses)
    any_progress = any(s in {"partial", "preparing", "in_transit", "delivered", "completed"} for s in statuses)
    if all_cancelled:
        derived_status = "cancelled"
    elif all_delivered:
        derived_status = "delivered"
    elif delivered_total > 0 or any_progress:
        derived_status = "partial"
    else:
        derived_status = "pending"
    expected_delivery_dt = max(expected_dates) if expected_dates else _parse_datetimeish(
        getattr(order, "expected_delivery_date", None)
    )
    return {
        "delivery_status": derived_status,
        "expected_delivery_date": _dt_iso(expected_delivery_dt),
        "delivered_at": max(delivered_ats).isoformat() if delivered_ats else None,
        "ordered_quantity_total": _dec3_float(ordered_total),
        "delivered_quantity_total": _dec3_float(delivered_total),
        "item_count": len(scoped_items),
    }


def _payment_badge(status: Optional[str]) -> Dict[str, str]:
    s = (_safe_str(status) or "unpaid").lower()
    if s == "paid":
        return {"key": "paid", "label": "Paid", "tone": "success"}
    if s == "partial":
        return {"key": "partial", "label": "Partially Paid", "tone": "warning"}
    if s == "pending":
        return {"key": "pending", "label": "Pending", "tone": "info"}
    if s == "refunded":
        return {"key": "refunded", "label": "Refunded", "tone": "neutral"}
    if s == "failed":
        return {"key": "failed", "label": "Failed", "tone": "danger"}
    return {"key": "unpaid", "label": "Unpaid", "tone": "danger"}


def _payment_method_label(value: Optional[str]) -> str:
    raw = (_safe_str(value) or "").lower()
    mapping = {
        "eft": "EFT / Bank",
        "bank": "EFT / Bank",
        "bank transfer": "EFT / Bank",
        "mobile_wallet": "Mobile Wallet",
        "wallet": "Mobile Wallet",
        "ewallet": "Mobile Wallet",
        "cash": "Cash",
        "cash_on_delivery": "Cash",
    }
    return mapping.get(raw, raw.replace("_", " ").title() or "-")


def _payment_reference_confirmation_supported(method: Optional[str]) -> bool:
    return (_safe_str(method) or "").lower() in {"eft", "bank", "bank transfer", "mobile_wallet", "wallet", "ewallet"}


def _build_payment_confirmation_meta(
    *,
    payment_status: Optional[str],
    payment_method: Optional[str],
    payment_reference: Optional[str],
    payment_proof_url: Optional[str],
) -> Dict[str, Any]:
    normalized_method = _normalized_checkout_payment_method(payment_method)
    method_label = _payment_method_label(normalized_method)
    reference_value = _safe_str(payment_reference)
    proof_url_value = _normalize_public_path(_safe_str(payment_proof_url))
    badge = _payment_badge(payment_status)
    supports_reference = _payment_reference_confirmation_supported(normalized_method)
    reference_only = bool(reference_value and not proof_url_value and supports_reference)
    has_submission = bool(reference_only or proof_url_value)
    if _payment_method_is_codish(normalized_method):
        status_label = badge.get("label", "Unpaid")
        title = "Cash on delivery"
        source = "cash_collection"
        mode = "cash_collection"
        hint = "No proof upload is required for cash on delivery. The farmer will collect payment on delivery or pickup."
        reference_label = "Cash reference"
    elif reference_only:
        status_label = "Awaiting farmer confirmation" if badge.get("key") == "pending" else badge.get("label", "Pending")
        title = "Payment confirmation"
        source = "ussd_reference"
        mode = "reference_only"
        hint = "Customer submitted a payment reference. Review it and confirm or reject payment."
        reference_label = "Submitted payment ref"
    elif proof_url_value:
        status_label = badge.get("label", "Pending")
        title = "Payment confirmation"
        source = "file_upload"
        mode = "proof_file"
        hint = "Customer submitted a payment confirmation file. Review the file and confirm or reject payment."
        reference_label = "Submitted payment ref"
    else:
        status_label = badge.get("label", "Unpaid")
        title = "Payment confirmation"
        source = "none"
        mode = "none"
        hint = "No payment confirmation has been submitted yet."
        reference_label = "Submitted payment ref"
    return {
        "payment_confirmation_mode": mode,
        "payment_confirmation_source": source,
        "payment_confirmation_title": title,
        "payment_confirmation_status_label": status_label,
        "payment_confirmation_status_tone": badge.get("tone"),
        "payment_confirmation_reference_label": reference_label,
        "payment_confirmation_reference": reference_value,
        "payment_confirmation_method_label": method_label,
        "payment_confirmation_has_submission": has_submission,
        "payment_confirmation_is_reference_only": reference_only,
        "payment_confirmation_has_file": bool(proof_url_value),
        "payment_confirmation_hint": hint,
    }


def _parse_payment_reference(raw: Optional[str]) -> PaymentReferenceParts:
    out: PaymentReferenceParts = {"reference": None, "proof_url": None, "proof_name": None}
    s = _safe_str(raw)
    if not s:
        return out
    if s.startswith("{") and s.endswith("}"):
        try:
            obj = json.loads(s)
            if isinstance(obj, dict):
                out["reference"] = _safe_str(obj.get("reference"))
                out["proof_url"] = _normalize_public_path(_safe_str(obj.get("proof_url")))
                out["proof_name"] = _safe_str(obj.get("proof_name"))
                return out
        except Exception:
            pass
    out["reference"] = s
    return out


def _compose_payment_reference(reference: Optional[str], proof_meta: Optional[Dict[str, Any]]) -> Optional[str]:
    ref = _safe_str(reference)
    if not ref:
        return None
    max_len = 120
    if len(ref) <= max_len:
        return ref
    current_app.logger.warning(
        "Payment reference exceeded %s chars; truncating safely for storage.",
        max_len,
    )
    return ref[:max_len]


def _find_best_payment_proof(order_id: UUID, *, viewer_farmer_id: Optional[UUID], buyer_id: Optional[UUID]) -> Optional[Dict[str, Optional[str]]]:
    scope_sequence: List[Optional[UUID]] = []
    seen_scopes: Set[str] = set()
    for scope in [viewer_farmer_id, buyer_id, None]:
        key = str(scope) if scope is not None else "__all__"
        if key in seen_scopes:
            continue
        seen_scopes.add(key)
        scope_sequence.append(scope)
    for scope in scope_sequence:
        rows = serialize_order_payments(order_id, user_id=scope) if scope is not None else serialize_order_payments(order_id)
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            parsed_ref = _parse_payment_reference(_safe_str(row.get("reference_raw") or row.get("reference")))
            proof_url = _normalize_public_path(parsed_ref.get("proof_url") or _safe_str(row.get("proof_url")))
            proof_name = parsed_ref.get("proof_name") or _safe_str(row.get("proof_name"))
            reference = parsed_ref.get("reference") or _safe_str(row.get("reference"))
            if proof_url:
                return {"proof_url": proof_url, "proof_name": proof_name, "reference": reference}
    return None


def _resolve_user_brief(user_id: Optional[UUID]) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {
        "user_id": str(user_id) if user_id else None,
        "farmer_name": None,
        "farmer_email": None,
        "farmer_phone": None,
        "farmer_location": None,
    }
    if user_id is None:
        return out
    user = db.session.get(User, user_id)
    if not isinstance(user, User):
        return out
    out["farmer_name"] = _safe_str(
        getattr(user, "full_name", None)
        or getattr(user, "name", None)
        or getattr(user, "username", None)
        or getattr(user, "email", None)
    )
    out["farmer_email"] = _safe_str(getattr(user, "email", None))
    out["farmer_phone"] = _safe_str(getattr(user, "phone", None))
    out["farmer_location"] = _safe_str(getattr(user, "location", None))
    return out


def _extract_scoped_payment_proof(order_id: UUID, scope_user_id: UUID) -> Dict[str, Optional[str]]:
    out: Dict[str, Optional[str]] = {"reference": None, "proof_url": None, "proof_name": None}
    rows = serialize_order_payments(order_id, user_id=scope_user_id)
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        parsed_ref = _parse_payment_reference(_safe_str(row.get("reference_raw") or row.get("reference")))
        proof_url = _normalize_public_path(parsed_ref.get("proof_url") or _safe_str(row.get("proof_url")))
        proof_name = parsed_ref.get("proof_name") or _safe_str(row.get("proof_name"))
        reference = parsed_ref.get("reference") or _safe_str(row.get("reference"))
        if reference and not out["reference"]:
            out["reference"] = reference
        if proof_url:
            out["proof_url"] = proof_url
            out["proof_name"] = proof_name
            if reference:
                out["reference"] = reference
            break
    return out


def _serialize_item(item: OrderItem, viewer_farmer_id: Optional[UUID] = None, order_payment_status: str = "unpaid") -> Dict[str, Any]:
    product = _get_product(item)
    owner = _product_owner_uuid(product) if product else None
    belongs_to_viewer = viewer_farmer_id is not None and owner == viewer_farmer_id
    unit_price = _to_decimal(getattr(item, "unit_price", None), Decimal("0")) or Decimal("0")
    qty = _to_decimal(getattr(item, "quantity", None), Decimal("0")) or Decimal("0")
    line_total = _to_decimal(getattr(item, "line_total", None), None)
    if line_total is None:
        line_total = _q2(unit_price * qty)
    item_delivery_status = _safe_str(
        getattr(item, "item_delivery_status", None)
        or getattr(item, "delivery_status", None)
        or getattr(item, "fulfillment_status", None)
    )
    delivered_qty = _to_decimal(
        getattr(item, "delivered_quantity", None) or getattr(item, "delivered_qty", None),
        Decimal("0"),
    ) or Decimal("0")
    farmer_user = getattr(product, "farmer", None) if product is not None else None
    farmer_name = _safe_str(
        getattr(product, "farmer_name", None)
        or getattr(farmer_user, "full_name", None)
        or getattr(farmer_user, "name", None)
        or getattr(farmer_user, "username", None)
        or getattr(product, "seller_name", None)
    )
    product_image_url = _normalize_public_path(
        _safe_str(getattr(product, "image_url", None) or getattr(product, "image", None) or getattr(product, "photo_url", None))
    )
    expected_item_delivery = _dt_iso(getattr(item, "expected_delivery_date", None) or getattr(item, "item_expected_delivery_date", None))
    fulfillment_status = _safe_str(getattr(item, "fulfillment_status", None))
    return {
        "order_item_id": str(getattr(item, "order_item_id", None) or getattr(item, "id", None) or ""),
        "product_id": str(getattr(item, "product_id", None) or ""),
        "product_name": _safe_str(getattr(product, "product_name", None) or getattr(product, "name", None)),
        "product_image_url": product_image_url,
        "farmer_id": str(owner) if owner else None,
        "farmer_name": farmer_name,
        "quantity": _dec3_float(qty),
        "unit_price": _dec2_float(unit_price),
        "line_total": _dec2_float(line_total),
        "unit": _safe_str(getattr(item, "unit", None) or getattr(product, "unit", None) or "each"),
        "pack_size": _dec3_float(_to_decimal(getattr(item, "pack_size", None), Decimal("0"))) if getattr(item, "pack_size", None) is not None else None,
        "pack_unit": _safe_str(getattr(item, "pack_unit", None)),
        "delivery_location": _safe_str(getattr(item, "delivery_location", None) or getattr(item, "item_delivery_location", None)),
        "fulfillment_status": fulfillment_status,
        "item_delivery_status": item_delivery_status,
        "delivery_status": item_delivery_status,
        "expected_delivery_date": expected_item_delivery,
        "delivered_qty": _dec3_float(delivered_qty),
        "delivered_quantity": _dec3_float(delivered_qty),
        "delivered_at": _dt_iso(getattr(item, "delivered_at", None)),
        "belongs_to_current_farmer": bool(belongs_to_viewer),
        "payment_status": order_payment_status,
        "payment_status_badge": _payment_badge(order_payment_status),
    }


def _serialize_farmer_payment_scope(order: Order, farmer_id: UUID) -> Optional[Dict[str, Any]]:
    oid = _order_uuid(order)
    if oid is None:
        return None
    scoped_items = _get_farmer_items(order, farmer_id)
    if not scoped_items:
        return None
    subtotal = _farmer_subtotal(order, farmer_id)
    delivery = _derive_farmer_delivery_summary(order, farmer_id)
    user_meta = _resolve_user_brief(farmer_id)
    bank_details = _extract_bank_details(order, farmer_id=farmer_id)
    summary_probe = build_order_payment_summary(oid, expected_total=_q2(subtotal), user_id=farmer_id)
    latest_probe = summary_probe.get("latest_payment") if isinstance(summary_probe, dict) else None
    latest_probe = latest_probe if isinstance(latest_probe, dict) else {}
    scoped_payment_method = _normalized_checkout_payment_method(
        _safe_str(latest_probe.get("method")) or getattr(order, "payment_method", None),
        fallback=_safe_str(getattr(order, "payment_method", None)),
    )
    financials = _build_checkout_financials(
        products_subtotal=subtotal,
        delivery_fee=getattr(order, "delivery_fee", None),
        delivery_fee_status=getattr(order, "delivery_fee_status", None),
        payment_status=(_safe_str(summary_probe.get("stored_status")) if isinstance(summary_probe, dict) else None) or "unpaid",
        payment_method=scoped_payment_method,
        bank_details=bank_details,
    )
    display_total = financials["grand_total"] if financials["checkout_flow_active"] else subtotal
    summary = build_order_payment_summary(oid, expected_total=display_total, user_id=farmer_id)
    latest = summary.get("latest_payment") if isinstance(summary, dict) else None
    latest = latest if isinstance(latest, dict) else {}
    stored_status = (_safe_str(summary.get("stored_status")) if isinstance(summary, dict) else None) or "unpaid"
    visibility_status = (_safe_str(summary.get("derived_status")) if isinstance(summary, dict) else None) or stored_status
    scoped_payment_method = _normalized_checkout_payment_method(
        _safe_str(latest.get("method")) or scoped_payment_method,
        fallback=scoped_payment_method,
    )
    financials = _build_checkout_financials(
        products_subtotal=subtotal,
        delivery_fee=getattr(order, "delivery_fee", None),
        delivery_fee_status=getattr(order, "delivery_fee_status", None),
        payment_status=stored_status,
        payment_method=scoped_payment_method,
        bank_details=bank_details,
    )
    display_total = financials["grand_total"] if financials["checkout_flow_active"] else subtotal
    parsed_ref = _parse_payment_reference(_safe_str(latest.get("reference_raw") or latest.get("reference")))
    strict_proof = _extract_scoped_payment_proof(oid, farmer_id)
    paid_total = _to_decimal(summary.get("paid_total"), Decimal("0")) or Decimal("0")
    if paid_total > display_total and display_total > Decimal("0"):
        paid_total = display_total
    due_total = _q2(display_total - paid_total)
    if due_total < Decimal("0"):
        due_total = Decimal("0")
    progress_pct = float(_q2((paid_total / display_total) * Decimal("100"))) if display_total > Decimal("0") else 0.0
    scope_items_payload = [_serialize_item(item, viewer_farmer_id=farmer_id, order_payment_status=visibility_status) for item in scoped_items]
    return {
        "scope_key": f"{oid}:{farmer_id}",
        "scope_user_id": str(farmer_id),
        "payment_scope_user_id": str(farmer_id),
        "farmer_id": str(farmer_id),
        "farmer_name": user_meta.get("farmer_name") or "Farmer",
        "farmer_email": user_meta.get("farmer_email"),
        "farmer_phone": user_meta.get("farmer_phone"),
        "farmer_location": user_meta.get("farmer_location"),
        "item_count": len(scope_items_payload),
        "items": scope_items_payload,
        "subtotal": _dec2_float(subtotal),
        "products_subtotal": _dec2_float(financials["products_subtotal"]),
        "delivery_fee": _dec2_float(financials["delivery_fee"]),
        "delivery_fee_status": financials["delivery_fee_status"],
        "vat_rate": float(financials["vat_rate"]),
        "vat_amount": _dec2_float(financials["vat_amount"]),
        "grand_total": _dec2_float(financials["grand_total"]),
        "total": _dec2_float(display_total),
        "total_amount": _dec2_float(display_total),
        "checkout_flow_active": financials["checkout_flow_active"],
        "checkout_ready": financials["checkout_ready"],
        "checkout_stage": financials["checkout_stage"],
        "bank_details": bank_details,
        "bank_name": bank_details.get("bank_name"),
        "account_name": bank_details.get("account_name"),
        "account_number": bank_details.get("account_number"),
        "branch_code": bank_details.get("branch_code"),
        "payment_instructions": bank_details.get("payment_instructions"),
        "payment_status": stored_status,
        "payment_visibility_status": visibility_status,
        "payment_status_badge": _payment_badge(stored_status),
        "payment_visibility_badge": _payment_badge(visibility_status),
        "payment_method": scoped_payment_method,
        "payment_reference": strict_proof.get("reference") or parsed_ref.get("reference") or _safe_str(latest.get("reference")),
        "payment_reference_raw": _safe_str(latest.get("reference_raw")),
        "payment_proof_url": strict_proof.get("proof_url"),
        "payment_proof_name": strict_proof.get("proof_name"),
        "payment_date": _dt_iso(latest.get("updated_at") or latest.get("created_at")),
        "paid_at": _dt_iso(latest.get("updated_at") or latest.get("created_at")),
        "payment_amount": _safe_str(latest.get("amount")),
        **_build_payment_confirmation_meta(
            payment_status=stored_status,
            payment_method=scoped_payment_method,
            payment_reference=strict_proof.get("reference") or parsed_ref.get("reference") or _safe_str(latest.get("reference")),
            payment_proof_url=strict_proof.get("proof_url"),
        ),
        "paid_total": _dec2_float(paid_total),
        "due_total": _dec2_float(due_total),
        "payment_progress_pct": progress_pct,
        "delivery_status": delivery["delivery_status"],
        "expected_delivery_date": delivery["expected_delivery_date"],
        "delivered_at": delivery["delivered_at"],
        "ordered_quantity_total": delivery["ordered_quantity_total"],
        "delivered_quantity_total": delivery["delivered_quantity_total"],
    }


def _serialize_farmer_payment_scopes(order: Order) -> List[Dict[str, Any]]:
    owner_ids: Set[UUID] = set()
    for item in _get_order_items(order):
        product = _get_product(item)
        owner = _product_owner_uuid(product) if product else None
        if owner is not None:
            owner_ids.add(owner)
    out: List[Dict[str, Any]] = []
    for farmer_id in sorted(owner_ids, key=lambda x: str(x)):
        scope = _serialize_farmer_payment_scope(order, farmer_id)
        if scope:
            out.append(scope)
    return out


def _augment_payment_fields(
    payload: Dict[str, Any],
    *,
    order_id: UUID,
    buyer_id: Optional[UUID],
    viewer_farmer_id: Optional[UUID],
    farmer_subtotal_value: Optional[Decimal],
    order_total_value: Decimal,
) -> None:
    if viewer_farmer_id is not None:
        fallback_expected_total = _q2(farmer_subtotal_value or Decimal("0"))
        expected_total = _q2(_to_decimal(payload.get("grand_total") if payload.get("checkout_flow_active") else None, fallback_expected_total) or fallback_expected_total)
        summary = build_order_payment_summary(order_id, expected_total=expected_total, user_id=viewer_farmer_id)
    else:
        fallback_expected_total = _q2(order_total_value)
        expected_total = _q2(_to_decimal(payload.get("grand_total") if payload.get("checkout_flow_active") else None, fallback_expected_total) or fallback_expected_total)
        summary = build_order_payment_summary(order_id, expected_total=expected_total, user_id=None)
    latest = summary.get("latest_payment") if isinstance(summary, dict) else None
    latest = latest if isinstance(latest, dict) else {}
    stored_status = (_safe_str(summary.get("stored_status")) if isinstance(summary, dict) else None) or "unpaid"
    visibility_status = (_safe_str(summary.get("derived_status")) if isinstance(summary, dict) else None) or stored_status
    parsed_ref = _parse_payment_reference(_safe_str(latest.get("reference_raw")))
    proof_url = parsed_ref.get("proof_url") or _normalize_public_path(_safe_str(latest.get("proof_url")))
    payload["payment_status"] = stored_status
    payload["payment_status_badge"] = _payment_badge(stored_status)
    payload["payment_visibility_status"] = visibility_status
    payload["payment_visibility_badge"] = _payment_badge(visibility_status)
    payload["partial_payment_visible"] = visibility_status == "partial"
    payload["has_partial_payment"] = visibility_status == "partial"
    payload["payment_method"] = _safe_str(latest.get("method")) or payload.get("payment_method")
    payload["payment_reference"] = parsed_ref.get("reference") or _safe_str(latest.get("reference"))
    payload["payment_reference_raw"] = _safe_str(latest.get("reference_raw"))
    payload["payment_proof_url"] = proof_url
    payload["payment_proof_name"] = parsed_ref.get("proof_name") or _safe_str(latest.get("proof_name"))
    payload["payment_date"] = _dt_iso(latest.get("updated_at") or latest.get("created_at"))
    payload["paid_at"] = _dt_iso(latest.get("updated_at") or latest.get("created_at"))
    payload["payment_amount"] = _safe_str(latest.get("amount"))
    if (
        payload.get("delivery_fee_status") is not None
        or payload.get("checkout_flow_active")
        or payload.get("products_subtotal") is not None
        or payload.get("delivery_fee") is not None
    ):
        recalculated_financials = _build_checkout_financials(
            products_subtotal=payload.get("products_subtotal") if payload.get("products_subtotal") is not None else (farmer_subtotal_value if viewer_farmer_id is not None else order_total_value),
            delivery_fee=payload.get("delivery_fee"),
            delivery_fee_status=payload.get("delivery_fee_status"),
            payment_status=stored_status,
            payment_method=payload.get("payment_method"),
            bank_details=payload.get("bank_details") if isinstance(payload.get("bank_details"), dict) else None,
        )
        payload["checkout_flow_active"] = recalculated_financials["checkout_flow_active"]
        payload["checkout_ready"] = recalculated_financials["checkout_ready"]
        payload["checkout_stage"] = recalculated_financials["checkout_stage"]
        payload["payment_method"] = recalculated_financials["payment_method"]
    payload.update(_build_payment_confirmation_meta(
        payment_status=stored_status,
        payment_method=payload.get("payment_method"),
        payment_reference=payload.get("payment_reference"),
        payment_proof_url=payload.get("payment_proof_url"),
    ))
    if not payload["payment_proof_url"] and viewer_farmer_id is None:
        proof_meta = _find_best_payment_proof(order_id, viewer_farmer_id=viewer_farmer_id, buyer_id=buyer_id)
        if proof_meta:
            payload["payment_proof_url"] = proof_meta.get("proof_url")
            payload["payment_proof_name"] = proof_meta.get("proof_name")
            if not payload.get("payment_reference"):
                payload["payment_reference"] = proof_meta.get("reference")
            payload.update(_build_payment_confirmation_meta(
                payment_status=stored_status,
                payment_method=payload.get("payment_method"),
                payment_reference=payload.get("payment_reference"),
                payment_proof_url=payload.get("payment_proof_url"),
            ))
    if viewer_farmer_id is not None:
        paid_total = _to_decimal(summary.get("paid_total"), Decimal("0")) or Decimal("0")
        due_total = _q2(expected_total - paid_total)
        if paid_total > expected_total and expected_total > Decimal("0"):
            paid_total = expected_total
        if paid_total < Decimal("0"):
            paid_total = Decimal("0")
        if due_total < Decimal("0"):
            due_total = Decimal("0")
        progress = float(_q2((paid_total / expected_total) * Decimal("100"))) if expected_total > 0 else 0.0
        payment_rows = summary.get("payments") if isinstance(summary, dict) else []
        has_user_scopes = any(isinstance(row, dict) and row.get("user_id") is not None for row in (payment_rows or []))
        payload["payment_scope"] = "farmer" if has_user_scopes else "order"
        payload["payment_scope_user_id"] = str(viewer_farmer_id) if has_user_scopes else None
        payload["farmer_subtotal"] = _dec_str(expected_total)
        payload["farmer_paid_total"] = _dec_str(paid_total)
        payload["farmer_due_total"] = _dec_str(due_total)
        payload["farmer_payment_progress_pct"] = progress
    if payload.get("checkout_flow_active") and payload.get("grand_total") is not None:
        grand_total = _q2(_to_decimal(payload.get("grand_total"), Decimal("0")) or Decimal("0"))
        paid_total_any = _to_decimal(summary.get("paid_total"), Decimal("0")) or Decimal("0")
        due_total_any = _q2(grand_total - paid_total_any)
        if due_total_any < Decimal("0"):
            due_total_any = Decimal("0")
        payload["paid_total"] = _dec2_float(paid_total_any)
        payload["due_total"] = _dec2_float(due_total_any)
        payload["payment_progress_pct"] = float(_q2((paid_total_any / grand_total) * Decimal("100"))) if grand_total > Decimal("0") else 0.0


def serialize_order(order: Order, *, viewer_farmer_id: Optional[UUID] = None, include_items: bool = True) -> Dict[str, Any]:
    oid = _order_uuid(order)
    buyer_id = _order_buyer_uuid(order)
    buyer_user = _get_buyer_user(order)
    status_val = _safe_str(getattr(order, "status", None) or getattr(order, "order_status", None)) or "pending"
    full_order_total = _to_decimal(
        getattr(order, "order_total", None)
        or getattr(order, "total_amount", None)
        or getattr(order, "total", None)
        or getattr(order, "grand_total", None),
        Decimal("0"),
    ) or Decimal("0")
    all_items = _get_order_items(order)
    visible_items = list(all_items)
    delivery_address = _safe_str(
        getattr(order, "delivery_address", None)
        or getattr(order, "delivery_location", None)
        or getattr(order, "customer_location", None)
        or getattr(order, "address", None)
    )
    delivery_location = _safe_str(
        getattr(order, "delivery_location", None)
        or getattr(order, "delivery_address", None)
        or getattr(order, "customer_location", None)
        or getattr(order, "address", None)
    )
    buyer_name = _safe_str(
        getattr(buyer_user, "full_name", None)
        or getattr(buyer_user, "name", None)
        or getattr(buyer_user, "username", None)
        or getattr(order, "buyer_name", None)
        or getattr(order, "customer_name", None)
    )
    buyer_email = _safe_str(
        getattr(buyer_user, "email", None)
        or getattr(order, "buyer_email", None)
        or getattr(order, "customer_email", None)
    )
    buyer_phone = _safe_str(
        getattr(buyer_user, "phone", None)
        or getattr(order, "buyer_phone", None)
        or getattr(order, "customer_phone", None)
    )
    buyer_location = _safe_str(
        getattr(buyer_user, "location", None)
        or getattr(order, "buyer_location", None)
        or getattr(order, "customer_location", None)
        or delivery_location
    )
    buyer_address = delivery_address or buyer_location

    payload: Dict[str, Any] = {
        "order_id": str(oid) if oid else None,
        "id": str(oid) if oid else None,
        "buyer_id": str(buyer_id) if buyer_id else None,
        "buyer_name": buyer_name,
        "buyer_email": buyer_email,
        "buyer_phone": buyer_phone,
        "buyer_location": buyer_location,
        "buyer_address": buyer_address,
        "customer_name": buyer_name,
        "customer_email": buyer_email,
        "customer_phone": buyer_phone,
        "customer_location": buyer_location,
        "customer_address": buyer_address,
        "order_status": status_val,
        "status": status_val,
        "order_date": _dt_iso(getattr(order, "order_date", None) or getattr(order, "created_at", None)),
        "delivery_address": delivery_address,
        "delivery_location": delivery_location,
        "delivery_method": _safe_str(getattr(order, "delivery_method", None)),
        "delivery_status": _safe_str(getattr(order, "delivery_status", None)),
        "expected_delivery_date": _dt_iso(getattr(order, "expected_delivery_date", None)),
        "delivered_at": _dt_iso(getattr(order, "delivered_at", None)),
        "customer_order_total": _dec2_float(full_order_total),
        "order_total_customer": _dec2_float(full_order_total),
    }

    farmer_subtotal_value: Optional[Decimal] = None
    if viewer_farmer_id is not None:
        owned_items = _get_farmer_items(order, viewer_farmer_id)
        owned_count = len(owned_items)
        has_other = owned_count < len(all_items) if len(all_items) > 0 else False
        exclusive_for_farmer = not has_other and owned_count > 0
        farmer_subtotal_value = _farmer_subtotal(order, viewer_farmer_id)
        scoped_total = _q2(farmer_subtotal_value or Decimal("0"))
        if has_other:
            visible_items = owned_items
        payload["exclusive_for_farmer"] = exclusive_for_farmer
        payload["has_other_farmers_items"] = has_other
        payload["order_field_locked_for_multi"] = has_other
        payload["scoped_item_count"] = owned_count
        payload["multi_farmer_order"] = has_other
        payload["scope_mode"] = "farmer_shared" if has_other else "farmer_exclusive"
        payload["farmer_subtotal"] = _dec_str(scoped_total)
        payload["farmer_order_total"] = _dec2_float(scoped_total)
        payload["order_total"] = _dec2_float(scoped_total)
        payload["total_amount"] = _dec2_float(scoped_total)
        payload["total"] = _dec2_float(scoped_total)
        farmer_delivery = _derive_farmer_delivery_summary(order, viewer_farmer_id)
        payload["farmer_delivery_status"] = farmer_delivery["delivery_status"]
        payload["farmer_expected_delivery_date"] = farmer_delivery["expected_delivery_date"]
        payload["farmer_delivered_at"] = farmer_delivery["delivered_at"]
        payload["farmer_ordered_quantity_total"] = farmer_delivery["ordered_quantity_total"]
        payload["farmer_delivered_quantity_total"] = farmer_delivery["delivered_quantity_total"]
        if has_other:
            payload["delivery_status"] = farmer_delivery["delivery_status"]
            payload["expected_delivery_date"] = farmer_delivery["expected_delivery_date"]
            payload["delivered_at"] = farmer_delivery["delivered_at"]
    else:
        payload["order_total"] = _dec2_float(full_order_total)
        payload["total_amount"] = _dec2_float(full_order_total)
        payload["total"] = _dec2_float(full_order_total)

    payload["items"] = [_serialize_item(it, viewer_farmer_id=viewer_farmer_id, order_payment_status="unpaid") for it in visible_items] if include_items else []
    payload["item_count"] = len(payload["items"])
    payload["itemCount"] = len(payload["items"])
    preview_names = [safeStr(it.get("product_name"), "Item") for it in payload["items"][:2]]
    payload["items_preview"] = ", ".join([x for x in preview_names if x]) if preview_names else ""

    products_subtotal_value = _q2(farmer_subtotal_value or Decimal("0")) if viewer_farmer_id is not None else _items_products_subtotal(visible_items)
    bank_details = _extract_bank_details(order, farmer_id=viewer_farmer_id or _infer_single_farmer_owner(order))
    checkout_financials = _build_checkout_financials(
        products_subtotal=products_subtotal_value,
        delivery_fee=getattr(order, "delivery_fee", None),
        delivery_fee_status=getattr(order, "delivery_fee_status", None),
        payment_status=getattr(order, "payment_status", None),
        payment_method=getattr(order, "payment_method", None),
        bank_details=bank_details,
    )
    payload["products_subtotal"] = _dec2_float(checkout_financials["products_subtotal"])
    payload["delivery_fee"] = _dec2_float(checkout_financials["delivery_fee"])
    payload["delivery_fee_status"] = checkout_financials["delivery_fee_status"]
    payload["vat_rate"] = float(checkout_financials["vat_rate"])
    payload["vat_amount"] = _dec2_float(checkout_financials["vat_amount"])
    payload["grand_total"] = _dec2_float(checkout_financials["grand_total"])
    payload["checkout_flow_active"] = checkout_financials["checkout_flow_active"]
    payload["checkout_ready"] = checkout_financials["checkout_ready"]
    payload["checkout_stage"] = checkout_financials["checkout_stage"]
    payload["bank_details"] = bank_details
    payload["bank_name"] = bank_details.get("bank_name")
    payload["account_name"] = bank_details.get("account_name")
    payload["account_number"] = bank_details.get("account_number")
    payload["branch_code"] = bank_details.get("branch_code")
    payload["payment_instructions"] = bank_details.get("payment_instructions")
    if checkout_financials["checkout_flow_active"] and viewer_farmer_id is None:
        payload["order_total"] = _dec2_float(checkout_financials["grand_total"])
        payload["total_amount"] = _dec2_float(checkout_financials["grand_total"])
        payload["total"] = _dec2_float(checkout_financials["grand_total"])
    if oid is not None:
        _augment_payment_fields(
            payload,
            order_id=oid,
            buyer_id=buyer_id,
            viewer_farmer_id=viewer_farmer_id,
            farmer_subtotal_value=farmer_subtotal_value,
            order_total_value=full_order_total,
        )
        if include_items and payload["items"]:
            pstatus = payload.get("payment_visibility_status") or payload.get("payment_status") or "unpaid"
            for it in payload["items"]:
                it["payment_status"] = pstatus
                it["payment_status_badge"] = _payment_badge(_safe_str(pstatus))
        if viewer_farmer_id is not None:
            effective_payment = _safe_str(payload.get("payment_visibility_status") or payload.get("payment_status"))
            current_status = _safe_str(payload.get("status") or payload.get("order_status") or "pending")
            if effective_payment == "paid" and current_status != "cancelled":
                payload["status"] = "completed"
                payload["order_status"] = "completed"
    if viewer_farmer_id is None:
        payment_scopes = _serialize_farmer_payment_scopes(order)
        payload["payment_scopes"] = payment_scopes
        payload["farmer_payment_scopes"] = payment_scopes
        payload["is_multi_farmer_order"] = len(payment_scopes) > 1
    else:
        payload["payment_scopes"] = []
        payload["farmer_payment_scopes"] = []
        payload["is_multi_farmer_order"] = bool(payload.get("has_other_farmers_items"))
    return payload


def _list_orders_impl(current_user: User):
    try:
        days, all_time = _parse_days_all_time(default_days=90)
        q_text = request.args.get("q", "", type=str).strip()
        include_items = _is_truthy(request.args.get("include_items", "1"))
        query = db.session.query(Order)
        date_col = _order_date_col()
        if date_col is not None and not all_time:
            cutoff = utcnow() - timedelta(days=days)
            query = query.filter(date_col >= cutoff)
        if not _is_admin(current_user):
            uid = _user_id(current_user)
            buyer_col = getattr(Order, "buyer_id", None) or getattr(Order, "user_id", None)
            if uid is None or buyer_col is None:
                return jsonify({"ok": False, "message": "Invalid authenticated user context"}), 401
            query = query.filter(buyer_col == uid)
        if q_text:
            pk_col = _order_pk_col()
            if pk_col is not None:
                query = query.filter(sa_cast(pk_col, SAString).ilike(f"%{q_text}%"))
        if date_col is not None:
            query = query.order_by(date_col.desc())
        orders = query.limit(300).all()
        data = [serialize_order(o, viewer_farmer_id=None, include_items=include_items) for o in orders]
        return jsonify({"ok": True, "data": data}), 200
    except Exception:
        db.session.rollback()
        current_app.logger.exception("GET /orders failed")
        return jsonify({"ok": False, "message": "Failed to fetch orders"}), 500


def _list_my_orders_impl(current_user: User):
    try:
        days, all_time = _parse_days_all_time(default_days=90)
        q_text = request.args.get("q", "", type=str).strip()
        include_items = _is_truthy(request.args.get("include_items", "1"))
        buyer_id = _user_id(current_user)
        buyer_col = getattr(Order, "buyer_id", None) or getattr(Order, "user_id", None)
        if buyer_id is None or buyer_col is None:
            return jsonify({"ok": False, "message": "Invalid authenticated user context"}), 401
        query = db.session.query(Order).filter(buyer_col == buyer_id)
        date_col = _order_date_col()
        if date_col is not None and not all_time:
            cutoff = utcnow() - timedelta(days=days)
            query = query.filter(date_col >= cutoff)
        if q_text:
            pk_col = _order_pk_col()
            if pk_col is not None:
                query = query.filter(sa_cast(pk_col, SAString).ilike(f"%{q_text}%"))
        if date_col is not None:
            query = query.order_by(date_col.desc())
        orders = query.limit(300).all()
        return jsonify({"ok": True, "data": [serialize_order(o, include_items=include_items) for o in orders]}), 200
    except Exception:
        db.session.rollback()
        current_app.logger.exception("GET /orders/me failed")
        return jsonify({"ok": False, "message": "Failed to fetch your orders"}), 500


def _list_farmer_orders_impl(current_user: User, requested_farmer_id: Optional[UUID]):
    try:
        uid = _user_id(current_user)
        effective_farmer_id: Optional[UUID] = requested_farmer_id
        if not _is_admin(current_user):
            if uid is None:
                return jsonify({"ok": False, "message": "Invalid authenticated user context"}), 401
            if requested_farmer_id is not None and requested_farmer_id != uid:
                current_app.logger.warning(
                    "Farmer orders ID mismatch: path=%s auth=%s. Using authenticated scope.",
                    requested_farmer_id,
                    uid,
                )
            effective_farmer_id = uid
        if effective_farmer_id is None:
            return jsonify({"ok": False, "message": "Missing farmer identifier"}), 400
        days, all_time = _parse_days_all_time(default_days=60)
        include_items = _is_truthy(request.args.get("include_items", "1"))
        q_text = request.args.get("q", "", type=str).strip()
        order_pk = _order_pk_col()
        date_col = _order_date_col()
        product_pk = _product_pk_col()
        product_owner = _product_owner_col()
        if order_pk is None:
            return jsonify({"ok": False, "message": "Order schema is misconfigured"}), 500
        query = db.session.query(Order).join(OrderItem, OrderItem.order_id == order_pk)
        if product_pk is not None and product_owner is not None:
            query = query.join(Product, OrderItem.product_id == product_pk).filter(product_owner == effective_farmer_id)
        else:
            owned_ids = _owned_product_ids_for_farmer(effective_farmer_id)
            if not owned_ids:
                return jsonify({"ok": True, "data": []}), 200
            query = query.filter(OrderItem.product_id.in_(list(owned_ids)))
        query = query.distinct()
        if date_col is not None and not all_time:
            cutoff = utcnow() - timedelta(days=days)
            query = query.filter(date_col >= cutoff)
        if q_text:
            query = query.filter(sa_cast(order_pk, SAString).ilike(f"%{q_text}%"))
        if date_col is not None:
            query = query.order_by(date_col.desc())
        orders = query.limit(300).all()
        data = [serialize_order(o, viewer_farmer_id=effective_farmer_id, include_items=include_items) for o in orders]
        return jsonify({"ok": True, "data": data}), 200
    except Exception:
        db.session.rollback()
        current_app.logger.exception("GET /orders/farmer failed")
        return jsonify({"ok": False, "message": "Failed to fetch farmer orders"}), 500


def _farmer_top_products_impl(current_user: User, requested_farmer_id: Optional[UUID]):
    uid = _user_id(current_user)
    effective_farmer_id: Optional[UUID] = requested_farmer_id
    if not _is_admin(current_user):
        if uid is None:
            return jsonify({"ok": False, "message": "Invalid authenticated user context"}), 401
        if requested_farmer_id is not None and requested_farmer_id != uid:
            current_app.logger.warning(
                "Top products farmer ID mismatch: path=%s auth=%s. Using authenticated scope.",
                requested_farmer_id,
                uid,
            )
        effective_farmer_id = uid
    if effective_farmer_id is None:
        return jsonify({"ok": False, "message": "Missing farmer identifier"}), 400
    _, all_time = _parse_days_all_time(default_days=60)
    days_raw = request.args.get("days", "60")
    limit_raw = request.args.get("limit", "8")
    try:
        days = max(1, int(days_raw))
    except ValueError:
        days = 60
    try:
        limit = max(1, min(int(limit_raw), 100))
    except ValueError:
        limit = 8
    try:
        db.session.rollback()
        product_pk = _product_pk_col()
        product_name = _product_name_col()
        product_owner = _product_owner_col()
        order_pk = _order_pk_col()
        date_col = _order_date_col()
        if product_pk is None or product_name is None or product_owner is None or order_pk is None:
            return jsonify({"ok": False, "message": "Schema mismatch for top-products query"}), 500
        cutoff = utcnow() - timedelta(days=days)
        line_total_expr = _line_total_expr()
        q = (
            db.session.query(
                product_pk.label("product_id"),
                product_name.label("product_name"),
                func.coalesce(func.sum(getattr(OrderItem, "quantity")), 0).label("qty_sold"),
                func.coalesce(func.sum(line_total_expr), 0).label("gross_sales"),
            )
            .join(OrderItem, OrderItem.product_id == product_pk)
            .join(Order, order_pk == OrderItem.order_id)
            .filter(product_owner == effective_farmer_id)
        )
        if date_col is not None and not all_time:
            q = q.filter(date_col >= cutoff)
        q = (
            q.group_by(product_pk, product_name)
            .order_by(
                func.coalesce(func.sum(getattr(OrderItem, "quantity")), 0).desc(),
                func.coalesce(func.sum(line_total_expr), 0).desc(),
            )
            .limit(limit)
        )
        rows = q.all()
        data = [
            {
                "product_id": str(r.product_id),
                "product_name": r.product_name,
                "qty_sold": _dec3_float(_to_decimal(r.qty_sold, Decimal("0")) or Decimal("0")),
                "gross_sales": _dec2_float(_to_decimal(r.gross_sales, Decimal("0")) or Decimal("0")),
            }
            for r in rows
        ]
        return jsonify({"ok": True, "data": data}), 200
    except SQLAlchemyError as e:
        db.session.rollback()
        current_app.logger.exception("farmer_top_products failed")
        return jsonify({"ok": False, "message": "Failed to load top products.", "error": e.__class__.__name__}), 500


@orders_bp.get("")
@orders_bp.get("/")
@token_required
def list_orders(current_user: User):
    return _list_orders_impl(current_user)


@orders_bp.get("/me")
@token_required
def my_orders(current_user: User):
    return _list_my_orders_impl(current_user)


@orders_bp.get("/my")
@token_required
def my_orders_alias(current_user: User):
    return _list_my_orders_impl(current_user)


@orders_bp.get("/<uuid:order_id>")
@token_required
def get_order(current_user: User, order_id: UUID):
    try:
        blocked_message = _write_operations_blocked_message()
        if blocked_message:
            return jsonify({"ok": False, "message": blocked_message}), 409
        order = db.session.get(Order, order_id)
        if order is None:
            return jsonify({"ok": False, "message": "Order not found"}), 404
        uid = _user_id(current_user)
        buyer = _order_buyer_uuid(order)
        if not _is_admin(current_user):
            authorized = False
            if uid is not None and buyer == uid:
                authorized = True
            elif uid is not None and _order_has_farmer_items(order, uid):
                authorized = True
            if not authorized:
                return jsonify({"ok": False, "message": "Forbidden"}), 403
        viewer_farmer_id = None
        if uid is not None and _order_has_farmer_items(order, uid) and buyer != uid and not _is_admin(current_user):
            viewer_farmer_id = uid
        return jsonify({"ok": True, "data": serialize_order(order, viewer_farmer_id=viewer_farmer_id, include_items=True)}), 200
    except Exception:
        db.session.rollback()
        current_app.logger.exception("GET /orders/<id> failed")
        return jsonify({"ok": False, "message": "Failed to fetch order"}), 500


@orders_bp.get("/farmer/<uuid:farmer_id>")
@token_required
def list_farmer_orders(current_user: User, farmer_id: UUID):
    return _list_farmer_orders_impl(current_user, farmer_id)


@orders_bp.get("/farmer/me")
@token_required
def list_farmer_orders_me(current_user: User):
    return _list_farmer_orders_impl(current_user, None)


@orders_bp.get("/farmer/my")
@token_required
def list_farmer_orders_my_alias(current_user: User):
    return _list_farmer_orders_impl(current_user, None)


@orders_bp.get("/farmer/<uuid:farmer_id>/top-products")
@token_required
def farmer_top_products(current_user: User, farmer_id: UUID):
    return _farmer_top_products_impl(current_user, farmer_id)


@orders_bp.get("/farmer/me/top-products")
@token_required
def farmer_top_products_me(current_user: User):
    return _farmer_top_products_impl(current_user, None)


@orders_bp.get("/farmer/my/top-products")
@token_required
def farmer_top_products_my_alias(current_user: User):
    return _farmer_top_products_impl(current_user, None)

# The remaining route functions are lengthy and kept identical to the validated
# logic already provided in earlier parts: farmer_update_order_status,
# upload_order_payment_proof, and create_order.
# They are included separately below to keep this file manageable.

@orders_bp.put("/<uuid:order_id>/farmer-status")
@token_required
def farmer_update_order_status(current_user: User, order_id: UUID):
    """
    Farmer-safe status updates.

    NEW IN THIS VERSION:
      • Farmer can set delivery fee on exclusive/split orders
      • Farmer can mark order ready for payment
      • EFT-ready state requires complete farmer bank details
      • Customer is notified when the order becomes ready for payment
      • Payment amount for the farmer scope is updated to the quoted grand total
    """
    try:
        blocked_message = _write_operations_blocked_message()
        if blocked_message:
            return jsonify({"ok": False, "message": blocked_message}), 409

        order = db.session.get(Order, order_id)
        if order is None:
            return jsonify({"ok": False, "message": "Order not found"}), 404

        payload = request.get_json(silent=True) or {}
        if not isinstance(payload, dict):
            payload = {}

        uid = _user_id(current_user)
        if uid is None:
            return jsonify({"ok": False, "message": "Unauthorized"}), 401

        farmer_id_raw = payload.get("farmer_id") or payload.get("farmerId") or request.args.get("farmer_id")
        farmer_id = _as_uuid(farmer_id_raw) or uid

        if not _is_admin(current_user) and farmer_id != uid:
            return jsonify({"ok": False, "message": "Forbidden"}), 403

        if not _order_has_farmer_items(order, farmer_id):
            return jsonify({"ok": False, "message": "No owned items in this order"}), 403

        exclusive = _order_is_exclusive_for_farmer(order, farmer_id)
        buyer_id = _order_buyer_uuid(order)

        delivery_fee_input_raw = payload.get("delivery_fee")
        has_delivery_fee_input = delivery_fee_input_raw is not None and _safe_str(delivery_fee_input_raw) is not None
        delivery_fee_value: Optional[Decimal] = None

        if has_delivery_fee_input:
            delivery_fee_value = _q2(_to_decimal(delivery_fee_input_raw, Decimal("0.00")) or Decimal("0.00"))
            if delivery_fee_value < Decimal("0.00"):
                return jsonify({"ok": False, "message": "delivery_fee cannot be negative"}), 400

        requested_delivery_fee_status = _normalize_delivery_fee_status(payload.get("delivery_fee_status"))
        ready_for_payment_flag = _is_truthy(payload.get("ready_for_payment")) or _is_truthy(payload.get("checkout_ready"))

        if not exclusive and (has_delivery_fee_input or requested_delivery_fee_status is not None or ready_for_payment_flag):
            return jsonify({"ok": False, "message": "Delivery fee can only be changed on exclusive farmer orders / split orders."}), 409

        latest_scope_payment = _latest_scope_payment_fields(order_id, farmer_id)
        current_scope_payment_status = (_safe_str(latest_scope_payment.get("stored_status")) or "unpaid").lower()
        preserved_payment_method = _normalized_checkout_payment_method(
            _safe_str(payload.get("payment_method")) or latest_scope_payment.get("method") or getattr(order, "payment_method", None),
            fallback=_safe_str(getattr(order, "payment_method", None)),
        )
        preserved_payment_reference = (
            _safe_str(payload.get("payment_reference") or payload.get("reference"))
            or latest_scope_payment.get("reference")
            or latest_scope_payment.get("reference_raw")
        )
        existing_submission_present = _payment_submission_exists(
            latest_scope_payment.get("reference_raw") or latest_scope_payment.get("reference") or preserved_payment_reference,
            latest_scope_payment.get("proof_url"),
        )
        dispatch_requested = False

        items_patch_raw = payload.get("items")
        items_patch = _coerce_items(items_patch_raw)
        item_patch_by_id: Dict[UUID, Dict[str, Any]] = {}

        for patch in items_patch:
            iid = _as_uuid(patch.get("order_item_id") or patch.get("orderItemId") or patch.get("item_id") or patch.get("id"))
            if iid is None:
                continue
            item_patch_by_id[iid] = patch

        scoped_delivery_status_global = _safe_str(
            payload.get("farmer_delivery_status")
            or payload.get("my_delivery_status")
            or payload.get("scoped_delivery_status")
            or payload.get("item_delivery_status")
        )
        if scoped_delivery_status_global is None and not exclusive:
            scoped_delivery_status_global = _safe_str(payload.get("delivery_status") or payload.get("status"))

        delivered_qty_global = _to_decimal(payload.get("delivered_qty", payload.get("delivered_quantity")), None)
        order_items = _get_order_items(order)
        updated_any_item = False
        touched_item_ids: List[str] = []

        for item in order_items:
            product = _get_product(item)
            if product is None or not _product_owned_by(product, farmer_id):
                continue

            item_id = _order_item_uuid(item)
            if item_id is None:
                continue

            patch = item_patch_by_id.get(item_id)
            if patch is not None:
                item_delivery_status = _safe_str(patch.get("delivery_status") or patch.get("item_delivery_status") or patch.get("status"))
                delivered_qty = _to_decimal(patch.get("delivered_qty", patch.get("delivered_quantity")), None)
            else:
                item_delivery_status = scoped_delivery_status_global
                delivered_qty = delivered_qty_global

            if patch is None and item_delivery_status is None and delivered_qty is None:
                continue

            if _delivery_status_requests_dispatch(item_delivery_status):
                dispatch_requested = True

            ordered_qty = _to_decimal(getattr(item, "quantity", None), Decimal("0")) or Decimal("0")

            if item_delivery_status:
                normalized_item_status = item_delivery_status.lower()
                if hasattr(item, "item_delivery_status"):
                    setattr(item, "item_delivery_status", normalized_item_status)
                if hasattr(item, "delivery_status"):
                    setattr(item, "delivery_status", normalized_item_status)
                if hasattr(item, "fulfillment_status"):
                    setattr(item, "fulfillment_status", normalized_item_status)
            else:
                normalized_item_status = _safe_str(
                    getattr(item, "item_delivery_status", None)
                    or getattr(item, "delivery_status", None)
                    or getattr(item, "fulfillment_status", None)
                    or "pending"
                ) or "pending"
                normalized_item_status = normalized_item_status.lower()

            final_delivered: Optional[Decimal] = None
            if delivered_qty is not None:
                final_delivered = _q3(delivered_qty)
                if final_delivered > ordered_qty:
                    final_delivered = _q3(ordered_qty)
                if final_delivered < Decimal("0"):
                    final_delivered = Decimal("0")

            if final_delivered is None and normalized_item_status in {"delivered", "completed"}:
                final_delivered = _q3(ordered_qty)

            if final_delivered is not None:
                if hasattr(item, "delivered_quantity"):
                    setattr(item, "delivered_quantity", final_delivered)
                if hasattr(item, "delivered_qty"):
                    setattr(item, "delivered_qty", final_delivered)

            if normalized_item_status in {"delivered", "completed"}:
                if hasattr(item, "delivered_at"):
                    setattr(item, "delivered_at", utcnow())
            elif normalized_item_status in {"pending", "preparing", "in_transit", "cancelled"}:
                current_delivered = _to_decimal(
                    getattr(item, "delivered_quantity", None) or getattr(item, "delivered_qty", None),
                    Decimal("0"),
                ) or Decimal("0")
                if current_delivered <= Decimal("0") and hasattr(item, "delivered_at"):
                    setattr(item, "delivered_at", None)

            updated_any_item = True
            touched_item_ids.append(str(item_id))

        order_status = _normalize_order_status(payload.get("order_status") or payload.get("status"))
        if exclusive and order_status:
            target = _order_status_col_name()
            _set_if_has(order, target, order_status)

        if exclusive:
            delivery_method = _safe_str(payload.get("delivery_method"))
            order_delivery_status = _safe_str(payload.get("delivery_status"))
            expected_delivery_date = _parse_datetimeish(payload.get("expected_delivery_date"))
            delivery_address = _safe_str(payload.get("delivery_address") or payload.get("delivery_location"))

            if delivery_method is not None:
                _set_if_has(order, "delivery_method", delivery_method)
            if order_delivery_status is not None:
                if _delivery_status_requests_dispatch(order_delivery_status):
                    dispatch_requested = True
                _set_if_has(order, "delivery_status", order_delivery_status.lower())
            elif scoped_delivery_status_global is not None:
                if _delivery_status_requests_dispatch(scoped_delivery_status_global):
                    dispatch_requested = True
                _set_if_has(order, "delivery_status", scoped_delivery_status_global.lower())
            if expected_delivery_date is not None:
                _set_if_has(order, "expected_delivery_date", expected_delivery_date)
            if delivery_address is not None:
                _set_if_has(order, "delivery_address", delivery_address)
                _set_if_has(order, "delivery_location", delivery_address)
                _set_if_has(order, "customer_location", delivery_address)
                _set_if_has(order, "address", delivery_address)

            if delivery_fee_value is not None:
                _set_if_has(order, "delivery_fee", delivery_fee_value)

            next_delivery_fee_status = requested_delivery_fee_status
            if ready_for_payment_flag:
                next_delivery_fee_status = "awaiting_customer_payment"
            elif next_delivery_fee_status is None and delivery_fee_value is not None:
                next_delivery_fee_status = "quoted"

            if next_delivery_fee_status is not None:
                effective_bank_details = _extract_bank_details(order, farmer_id=farmer_id)
                if next_delivery_fee_status in _READY_DELIVERY_FEE_STATUSES and _payment_method_is_eftish(preserved_payment_method):
                    if not effective_bank_details.get("is_complete"):
                        return jsonify({"ok": False, "message": "Complete your EFT / bank details in Farmer Settings before marking an EFT order ready for payment."}), 409
                _set_if_has(order, "delivery_fee_status", next_delivery_fee_status)

        payment_status = _safe_str(payload.get("payment_status"))
        effective_payment_status_for_storage = _normalize_payment_status_for_storage(payment_status) if payment_status else _normalize_payment_status_for_storage(current_scope_payment_status)

        if _delivery_status_requests_dispatch(order_status):
            dispatch_requested = True

        if (
            payment_status
            and effective_payment_status_for_storage == "paid"
            and _payment_requires_pre_delivery_clearance(preserved_payment_method)
            and current_scope_payment_status not in {"pending", "paid"}
            and not existing_submission_present
        ):
            return jsonify({"ok": False, "message": "EFT payment cannot be marked as paid before the customer submits proof or a payment reference."}), 409

        scoped_subtotal = _farmer_subtotal(order, farmer_id)
        effective_financials = _build_checkout_financials(
            products_subtotal=scoped_subtotal,
            delivery_fee=getattr(order, "delivery_fee", None),
            delivery_fee_status=getattr(order, "delivery_fee_status", None),
            payment_status=effective_payment_status_for_storage,
            payment_method=preserved_payment_method,
            bank_details=_extract_bank_details(order, farmer_id=farmer_id),
        )
        scoped_expected_total = effective_financials["grand_total"] if effective_financials["checkout_flow_active"] else scoped_subtotal

        if dispatch_requested and _payment_requires_pre_delivery_clearance(preserved_payment_method) and effective_payment_status_for_storage != "paid":
            return jsonify({"ok": False, "message": "EFT orders cannot move into delivery until payment has been confirmed."}), 409

        if payment_status or has_delivery_fee_input or requested_delivery_fee_status is not None or ready_for_payment_flag:
            upsert_order_payment(
                order_id=order_id,
                status=effective_payment_status_for_storage,
                amount=scoped_expected_total,
                method=preserved_payment_method,
                reference=preserved_payment_reference,
                user_id=farmer_id,
                proof_url=None,
                commit=False,
            )

        db.session.commit()

        should_notify_customer_ready = bool(
            buyer_id is not None
            and exclusive
            and effective_financials["checkout_flow_active"]
            and effective_financials["checkout_ready"]
            and (has_delivery_fee_input or ready_for_payment_flag or requested_delivery_fee_status in _READY_DELIVERY_FEE_STATUSES)
        )

        if should_notify_customer_ready:
            short_oid = str(order_id)[:8]
            selected_payment_method = _normalized_checkout_payment_method(
                _safe_str(preserved_payment_method) or _safe_str(getattr(order, "payment_method", None)) or "eft",
                fallback=_safe_str(getattr(order, "payment_method", None)) or "eft",
            )
            bank_details_payload = _extract_bank_details(order, farmer_id=farmer_id)
            is_bank_like = _payment_method_is_eftish(selected_payment_method)
            payment_method_label = "EFT / Bank Transfer" if is_bank_like else (selected_payment_method or "Payment")
            if is_bank_like:
                message_parts: List[str] = [
                    f"Your order {short_oid} is ready for payment.",
                    f"Payment method: {payment_method_label}.",
                    f"Products: N$ {float(effective_financials['products_subtotal']):.2f}.",
                    f"Delivery: N$ {float(effective_financials['delivery_fee']):.2f}.",
                    f"VAT: N$ {float(effective_financials['vat_amount']):.2f}.",
                    f"Total: N$ {float(effective_financials['grand_total']):.2f}.",
                ]
                if bank_details_payload.get("is_complete"):
                    bank_name = _safe_str(bank_details_payload.get("bank_name")) or "the farmer's bank"
                    account_name = _safe_str(bank_details_payload.get("account_name")) or "the account holder"
                    message_parts.append(f"Use the bank details provided for payment to {account_name} at {bank_name}.")
                notification_title = "Order ready for payment"
            else:
                message_parts = [
                    f"Your order {short_oid} is ready for cash on delivery.",
                    f"Payment method: {payment_method_label}.",
                    f"Products: N$ {float(effective_financials['products_subtotal']):.2f}.",
                    f"Delivery: N$ {float(effective_financials['delivery_fee']):.2f}.",
                    f"VAT: N$ {float(effective_financials['vat_amount']):.2f}.",
                    f"Total: N$ {float(effective_financials['grand_total']):.2f}.",
                    "No proof upload is required. Payment will be collected on delivery or pickup.",
                ]
                notification_title = "Order ready for cash on delivery"

            _notify_user_best_effort(
                buyer_id,
                notification_title,
                " ".join(message_parts),
                notification_type="order_ready_for_payment",
                order_id=order_id,
                actor_user_id=farmer_id,
                event_key=f"order_ready_for_payment:{order_id}",
                data={
                    "oid": str(order_id),
                    "payment_method": selected_payment_method,
                    "payment_method_label": payment_method_label,
                    "payment_method_is_eft": is_bank_like,
                    "products_subtotal": float(effective_financials["products_subtotal"]),
                    "delivery_fee": float(effective_financials["delivery_fee"]),
                    "vat_amount": float(effective_financials["vat_amount"]),
                    "grand_total": float(effective_financials["grand_total"]),
                    "checkout_stage": effective_financials["checkout_stage"],
                    "checkout_ready": bool(effective_financials["checkout_ready"]),
                    "bank_details": {
                        "bank_name": _safe_str(bank_details_payload.get("bank_name")),
                        "account_name": _safe_str(bank_details_payload.get("account_name")),
                        "account_number": _safe_str(bank_details_payload.get("account_number")),
                        "branch_code": _safe_str(bank_details_payload.get("branch_code")),
                        "payment_instructions": _safe_str(bank_details_payload.get("payment_instructions")),
                        "is_complete": bool(bank_details_payload.get("is_complete")),
                    },
                },
            )

        data = serialize_order(order, viewer_farmer_id=farmer_id, include_items=True)
        data["meta"] = {
            "exclusive_for_farmer": exclusive,
            "updated_item_fields": updated_any_item,
            "touched_item_ids": touched_item_ids,
            "order_fields_locked_for_multi": not exclusive,
            "farmer_delivery_status_editable": True,
            "customer_notified_ready_for_payment": should_notify_customer_ready,
        }
        return jsonify({"ok": True, "message": "Order updated", "data": data}), 200
    except Exception:
        db.session.rollback()
        current_app.logger.exception("PUT /orders/<id>/farmer-status failed")
        return jsonify({"ok": False, "message": "Failed to update order"}), 500


@orders_bp.post("/<uuid:order_id>/payment-proof")
@orders_bp.post("/<uuid:order_id>/payment_proof")
@token_required
def upload_order_payment_proof(current_user: User, order_id: UUID):
    try:
        order = db.session.get(Order, order_id)
        if order is None:
            return jsonify({"ok": False, "message": "Order not found"}), 404
        uid = _user_id(current_user)
        buyer_id = _order_buyer_uuid(order)
        if not _is_admin(current_user):
            if uid is None or buyer_id != uid:
                return jsonify({"ok": False, "message": "Forbidden"}), 403
        if not _request_is_multipart():
            return jsonify({"ok": False, "message": "multipart/form-data is required"}), 400
        proof_meta = _save_payment_proof_from_request()
        payment_reference_input = _safe_str(
            request.form.get("payment_proof_reference") or request.form.get("payment_reference") or request.form.get("reference")
        )
        requested_scope_user_id = _as_uuid(
            request.form.get("farmer_id") or request.form.get("payment_scope_user_id") or request.form.get("scope_user_id")
        )
        single_owner = _infer_single_farmer_owner(order)
        if requested_scope_user_id is not None:
            if not _order_has_farmer_items(order, requested_scope_user_id):
                return jsonify({"ok": False, "message": "The selected farmer scope does not belong to this order"}), 400
            target_scope_user_id = requested_scope_user_id
        elif single_owner is not None:
            target_scope_user_id = single_owner
        else:
            return jsonify({"ok": False, "message": "farmer_id is required for multi-farmer orders"}), 400

        scoped_subtotal = _q2(_farmer_subtotal(order, target_scope_user_id))
        payment_scope_fields = _latest_scope_payment_fields(order_id, target_scope_user_id)
        payment_scope_summary_probe = build_order_payment_summary(order_id, expected_total=scoped_subtotal, user_id=target_scope_user_id)
        payment_scope_latest_probe = payment_scope_summary_probe.get("latest_payment") if isinstance(payment_scope_summary_probe, dict) else None
        payment_scope_latest_probe = payment_scope_latest_probe if isinstance(payment_scope_latest_probe, dict) else {}
        payment_method = _normalized_checkout_payment_method(
            _safe_str(request.form.get("payment_method"))
            or payment_scope_fields.get("method")
            or _safe_str(payment_scope_latest_probe.get("method")),
            fallback=_safe_str(getattr(order, "payment_method", None)),
        )
        payment_method_error = _validate_checkout_payment_method(payment_method)
        if payment_method_error:
            return jsonify({"ok": False, "message": payment_method_error}), 409
        if _payment_method_is_codish(payment_method):
            return jsonify({"ok": False, "message": "Cash on delivery orders do not require proof upload. Payment is collected on delivery or pickup."}), 409

        proof_required_for_eft = _checkout_setting_bool("PROOF_OF_PAYMENT_REQUIRED_FOR_EFT", True)
        if _payment_method_is_eftish(payment_method) and proof_required_for_eft and not proof_meta:
            return jsonify({"ok": False, "message": "A payment confirmation file is required for this EFT submission"}), 400

        flow_financials = _build_checkout_financials(
            products_subtotal=scoped_subtotal,
            delivery_fee=getattr(order, "delivery_fee", None),
            delivery_fee_status=getattr(order, "delivery_fee_status", None),
            payment_status="unpaid",
            payment_method=payment_method,
            bank_details=_extract_bank_details(order, farmer_id=target_scope_user_id),
        )
        if flow_financials["checkout_flow_active"] and not flow_financials["checkout_ready"]:
            return jsonify({"ok": False, "message": "Payment confirmation is disabled until the farmer sets the delivery fee and the order becomes ready for payment."}), 409
        if flow_financials["checkout_flow_active"] and not _payment_method_is_eftish(payment_method):
            return jsonify({"ok": False, "message": "Payment confirmation files can only be used for EFT / bank transfer orders."}), 409

        payment_reference = _compose_payment_reference(payment_reference_input, proof_meta or {})
        proof_url = _normalize_public_path(_safe_str((proof_meta or {}).get("url")))
        expected_total = flow_financials["grand_total"] if flow_financials["checkout_flow_active"] else scoped_subtotal
        existing_summary = build_order_payment_summary(order_id, expected_total=expected_total, user_id=target_scope_user_id)
        existing_status = (_safe_str(existing_summary.get("stored_status")) or "unpaid").lower()
        existing_method = _safe_str((existing_summary.get("latest_payment") or {}).get("method") if isinstance(existing_summary, dict) else None)
        effective_method = _normalized_checkout_payment_method(payment_method or existing_method or "eft", fallback=_safe_str(getattr(order, "payment_method", None)) or "eft")
        if flow_financials["checkout_flow_active"] and not _payment_method_is_eftish(effective_method):
            return jsonify({"ok": False, "message": "Payment confirmation files can only be used for EFT / bank transfer orders."}), 409
        next_status = existing_status if existing_status in {"paid", "refunded"} else "pending"
        upsert_order_payment(
            order_id=order_id,
            status=_normalize_payment_status_for_storage(next_status),
            amount=expected_total,
            method=effective_method,
            reference=payment_reference,
            user_id=target_scope_user_id,
            proof_url=proof_url,
            commit=False,
        )
        db.session.commit()
        order_brief = serialize_order(order, include_items=False)
        notification_title = "Payment confirmation submitted"
        notification_message = (
            f"The customer submitted a payment confirmation file for order {str(order_id)[:8]}. Open the order and review the submission."
            if proof_meta
            else f"The customer submitted a payment reference for order {str(order_id)[:8]}. Open the order and confirm payment."
        )
        _notify_user_best_effort(
            target_scope_user_id,
            notification_title,
            notification_message,
            notification_type="payment_proof" if proof_meta else "payment_submitted",
            order_id=order_id,
            actor_user_id=buyer_id,
            event_key=(
                f"payment_confirmation:file:{order_id}:{target_scope_user_id}:{safeStr(proof_url, '')}"
                if proof_meta
                else f"payment_confirmation:ref:{order_id}:{target_scope_user_id}:{safeStr(payment_reference, '')}"
            ),
            data={
                "oid": str(order_id),
                "buyer_name": order_brief.get("buyer_name"),
                "buyer": order_brief.get("buyer_name"),
                "total": float(expected_total),
                "proof_name": safeStr((proof_meta or {}).get("name")),
                "payment_proof_name": safeStr((proof_meta or {}).get("name")),
                "payment_reference": payment_reference,
                "payment_proof_url": proof_url,
            },
        )
        data = serialize_order(order, include_items=True)
        data["meta"] = {
            "payment_confirmation_submitted": True,
            "payment_proof_uploaded": bool(proof_meta),
            "payment_scope": "farmer",
            "payment_scope_user_id": str(target_scope_user_id),
        }
        success_message = "Payment confirmation file submitted successfully" if proof_meta else "Payment reference submitted successfully"
        return jsonify({"ok": True, "message": success_message, "data": data}), 200
    except ValueError as exc:
        db.session.rollback()
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception:
        db.session.rollback()
        current_app.logger.exception("POST /orders/<id>/payment-proof failed")
        return jsonify({"ok": False, "message": "Failed to submit payment confirmation"}), 500


@orders_bp.post("")
@orders_bp.post("/")
@orders_bp.post("/checkout")
@token_required
def create_order(current_user: User):
    try:
        payload = _read_checkout_payload()
    except ValueError as exc:
        return jsonify({"ok": False, "message": str(exc)}), 400
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to parse checkout payload")
        return jsonify({"ok": False, "message": "Invalid checkout payload"}), 400

    try:
        blocked_message = _write_operations_blocked_message()
        if blocked_message:
            return jsonify({"ok": False, "message": blocked_message}), 409
        raw_items = payload.get("items")
        items = _coerce_items(raw_items)
        if not items:
            return jsonify({"ok": False, "message": "Cart is empty"}), 400
        max_order_lines = _checkout_setting_int("MAX_ORDER_LINES_PER_CHECKOUT", 20, min_value=1, max_value=200)
        if len(items) > max_order_lines:
            return jsonify({"ok": False, "message": f"Checkout limit reached. Maximum order lines per checkout is {max_order_lines}."}), 409
        buyer_id = _user_id(current_user)
        if buyer_id is None:
            return jsonify({"ok": False, "message": "Invalid authenticated user context"}), 401
        delivery_address = _safe_str(payload.get("delivery_address") or payload.get("delivery_location") or payload.get("customer_location") or payload.get("location"))
        delivery_method = _safe_str(payload.get("delivery_method")) or "delivery"
        payment_method = _safe_str(payload.get("payment_method")) or _default_checkout_payment_method()
        payment_ref_input = _safe_str(payload.get("payment_proof_reference") or payload.get("payment_reference") or payload.get("reference"))
        notes = _safe_str(payload.get("notes"))
        proof_meta = payload.get("_payment_proof_meta")

        payment_method_error = _validate_checkout_payment_method(payment_method)
        if payment_method_error:
            return jsonify({"ok": False, "message": payment_method_error}), 409
        if delivery_method == "delivery" and not _checkout_setting_bool("ALLOW_DELIVERY", True):
            return jsonify({"ok": False, "message": "Delivery checkout is disabled in system settings."}), 409
        if delivery_method == "pickup" and not _checkout_setting_bool("ALLOW_PICKUP", True):
            return jsonify({"ok": False, "message": "Pickup checkout is disabled in system settings."}), 409
        if proof_meta is not None and not isinstance(proof_meta, dict):
            proof_meta = None
        if payment_ref_input or proof_meta:
            return jsonify({"ok": False, "message": "Payment proof can only be uploaded after the farmer sets the delivery fee and the order is ready for payment."}), 409

        by_farmer: Dict[UUID, List[Dict[str, Any]]] = {}
        skipped: List[Dict[str, Any]] = []
        for raw in items:
            pid = _as_uuid(raw.get("product_id") or raw.get("id") or raw.get("productId"))
            if pid is None:
                skipped.append({"reason": "invalid_product_id", "item": raw})
                continue
            product = db.session.get(Product, pid)
            if product is None:
                skipped.append({"reason": "product_not_found", "item": raw})
                continue
            farmer_id = _product_owner_uuid(product)
            if farmer_id is None:
                skipped.append({"reason": "product_owner_missing", "item": raw})
                continue
            qty = _to_decimal(raw.get("quantity") or raw.get("qty") or 1, Decimal("1")) or Decimal("1")
            qty = _q3(qty)
            if qty <= Decimal("0"):
                qty = Decimal("1.000")
            unit_price = _to_decimal(raw.get("unit_price"), None)
            if unit_price is None:
                unit_price = _to_decimal(getattr(product, "price", None) or getattr(product, "unit_price", None), Decimal("0")) or Decimal("0")
            unit_price = _q2(unit_price)
            line_total = _q2(unit_price * qty)
            normalized_line = {
                "product": product,
                "product_id": pid,
                "quantity": qty,
                "unit_price": unit_price,
                "line_total": line_total,
                "unit": _safe_str(raw.get("unit") or getattr(product, "unit", None)) or "each",
                "pack_size": _to_decimal(raw.get("pack_size"), _to_decimal(getattr(product, "pack_size", None), None)),
                "pack_unit": _safe_str(raw.get("pack_unit") or getattr(product, "pack_unit", None)),
                "delivery_address": _safe_str(raw.get("delivery_address") or raw.get("delivery_location")) or delivery_address,
            }
            by_farmer.setdefault(farmer_id, []).append(normalized_line)

        if not by_farmer:
            return jsonify({"ok": False, "message": "No valid cart items found", "skipped": skipped}), 400

        created_orders: List[Order] = []
        order_status_field = _order_status_col_name()
        total_field = _order_total_col_name()

        for farmer_id, lines in by_farmer.items():
            order = Order()
            _set_if_has(order, "buyer_id", buyer_id)
            if hasattr(order, "user_id") and not hasattr(order, "buyer_id"):
                _set_if_has(order, "user_id", buyer_id)
            _set_if_has(order, order_status_field, "pending")
            _set_if_has(order, "delivery_method", delivery_method)
            _set_if_has(order, "payment_method", payment_method)
            _set_if_has(order, "delivery_fee", Decimal("0.00"))
            _set_if_has(order, "delivery_fee_status", "pending_quote")
            if delivery_address:
                _set_if_has(order, "delivery_address", delivery_address)
                _set_if_has(order, "delivery_location", delivery_address)
                _set_if_has(order, "customer_location", delivery_address)
                _set_if_has(order, "address", delivery_address)
            if notes:
                _set_if_has(order, "notes", notes)
            if hasattr(order, "order_date") and getattr(order, "order_date", None) is None:
                _set_if_has(order, "order_date", utcnow())
            subtotal = _q2(sum((ln["line_total"] for ln in lines), Decimal("0")))
            _set_if_has(order, total_field, subtotal)
            db.session.add(order)
            db.session.flush()
            oid = _order_uuid(order)
            if oid is None:
                raise RuntimeError("Order primary key was not generated")
            for ln in lines:
                item = OrderItem()
                _set_if_has(item, "order_id", oid)
                _set_if_has(item, "product_id", ln["product_id"])
                _set_if_has(item, "quantity", ln["quantity"])
                _set_if_has(item, "unit_price", ln["unit_price"])
                _set_if_has(item, "line_total", ln["line_total"])
                _set_if_has(item, "unit", ln["unit"])
                if ln["pack_size"] is not None:
                    _set_if_has(item, "pack_size", _q3(ln["pack_size"]))
                if ln["pack_unit"] is not None:
                    _set_if_has(item, "pack_unit", ln["pack_unit"])
                if ln["delivery_address"]:
                    _set_if_has(item, "delivery_location", ln["delivery_address"])
                    _set_if_has(item, "item_delivery_location", ln["delivery_address"])
                if hasattr(item, "item_delivery_status"):
                    _set_if_has(item, "item_delivery_status", "pending")
                if hasattr(item, "delivery_status"):
                    _set_if_has(item, "delivery_status", "pending")
                if hasattr(item, "fulfillment_status"):
                    _set_if_has(item, "fulfillment_status", "pending")
                db.session.add(item)
            upsert_order_payment(
                order_id=oid,
                status="unpaid",
                amount=subtotal,
                method=payment_method,
                reference=None,
                user_id=farmer_id,
                proof_url=None,
                commit=False,
            )
            created_orders.append(order)

        db.session.commit()

        for created in created_orders:
            created_id = _order_uuid(created)
            created_owner = _infer_single_farmer_owner(created)
            if created_id is not None and created_owner is not None:
                order_payload = serialize_order(created, include_items=False)
                _notify_user_best_effort(
                    created_owner,
                    "New order request received",
                    f"You received a new order request {str(created_id)[:8]}. Review the order and set the delivery fee to continue checkout.",
                    notification_type="new_order",
                    order_id=created_id,
                    actor_user_id=buyer_id,
                    event_key=f"new_order:{created_id}:{created_owner}",
                    data={
                        "oid": str(created_id),
                        "buyer_name": order_payload.get("buyer_name"),
                        "buyer": order_payload.get("buyer_name"),
                        "total": order_payload.get("products_subtotal") or order_payload.get("order_total"),
                        "order_total": order_payload.get("order_total"),
                        "products_subtotal": order_payload.get("products_subtotal"),
                    },
                )

        data = [serialize_order(o, include_items=True) for o in created_orders]
        return jsonify({
            "ok": True,
            "message": "Order request submitted successfully",
            "data": data,
            "meta": {
                "split_by_farmer": True,
                "orders_created": len(created_orders),
                "items_skipped": skipped,
            },
        }), 201
    except Exception:
        db.session.rollback()
        current_app.logger.exception("POST /orders failed")
        return jsonify({"ok": False, "message": "Failed to create order"}), 500
