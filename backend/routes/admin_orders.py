# ============================================================================
# backend/routes/admin_orders.py — Admin Order Management + Audit Hooks (JWT)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin-only endpoints to view/update orders:
#     • GET   /api/admin/orders
#     • GET   /api/admin/orders/<id>
#     • PATCH /api/admin/orders/<id>
#
# UPDATED DESIGN:
#   ✅ Adds USER ACTIVITY audit events for:
#        - admin_list_orders
#        - admin_view_order_detail
#        - admin_update_order
#   ✅ Adds ADMIN GOVERNANCE audit events for:
#        - update_order_status
#        - update_order_delivery_status
#        - update_order_payment
#   ✅ Fixes a latent bug:
#        Order model does NOT have payment_status / paid_at columns.
#        Payment changes must go through the payments table/service.
#   ✅ Returns enriched order payload with latest payment + payment summary
#   ✅ Preserves existing route shapes so admin endpoints remain stable
#
# IMPORTANT AUDIT BOUNDARY:
#   - user_activity_events => admin browsing / list usage / endpoint usage
#   - admin_audit_log      => privileged order/payment state changes
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional, cast

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import desc, select
from sqlalchemy.orm import selectinload

from backend.database.db import db
from backend.models.order import Order
from backend.models.payment import Payment
from backend.models.user import ROLE_ADMIN, User
from backend.services.orders.serialization import build_buyer_map, serialize_order
from backend.services.audit_logger import AuditLogger
from backend.services.payment_service import (
    build_order_payment_summary,
    serialize_latest_order_payment,
    serialize_order_payments,
    upsert_order_payment,
)
from backend.utils.require_auth import require_access_token

admin_orders_bp = Blueprint("admin_orders", __name__)

_ALLOWED_ORDER_STATUSES = {"pending", "completed", "cancelled"}
_ALLOWED_DELIVERY_STATUSES = {"pending", "processing", "dispatched", "delivered", "cancelled"}
_ALLOWED_PAYMENT_STATUSES = {"unpaid", "paid", "pending", "failed", "refunded"}


# --------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------
def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


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
    try:
        if value is None or value == "":
            return default
        return Decimal(str(value))
    except Exception:
        return default


def _parse_dt(value: Any) -> Optional[datetime]:
    """
    Accept datetime / ISO string / YYYY-MM-DD.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    raw = str(value).strip()
    if not raw:
        return None
    try:
        if raw.endswith("Z"):
            raw = raw[:-1]
        if len(raw) == 10 and raw[4] == "-" and raw[7] == "-":
            return datetime.fromisoformat(raw + "T00:00:00")
        return datetime.fromisoformat(raw)
    except Exception:
        return None


def _int_qp(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = request.args.get(name)
    try:
        value = int(str(raw).strip())
    except Exception:
        value = default
    return max(min_v, min(max_v, value))


def _bool_qp(name: str, default: bool = False) -> bool:
    raw = str(request.args.get(name) or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "y", "on"}


def _request_session_id() -> Optional[str]:
    header_value = (
        request.headers.get("X-Session-ID")
        or request.headers.get("X-Client-Session")
        or request.headers.get("X-Device-Session")
    )
    if header_value:
        return str(header_value).strip()[:128] or None

    body = request.get_json(silent=True) or {}
    if isinstance(body, dict):
        raw = body.get("sessionId") or body.get("session_id")
        if raw is not None:
            return str(raw).strip()[:128] or None

    return None


def _client_ip() -> Optional[str]:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()[:64] or None
    return request.remote_addr or None


def _user_agent() -> Optional[str]:
    ua = request.headers.get("User-Agent")
    return ua[:256] if ua else None


# --------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------
def _current_user() -> Optional[User]:
    u = getattr(g, "current_user", None)
    if isinstance(u, User):
        return u

    u2 = getattr(request, "current_user", None)
    if isinstance(u2, User):
        return u2

    return None


def _admin_guard() -> Optional[Response]:
    u = _current_user()
    if not isinstance(u, User):
        return _json({"success": False, "message": "Authentication required"}, 401)
    if u.role != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)
    return None


def _current_admin_uuid() -> Optional[uuid.UUID]:
    u = _current_user()
    if u is None:
        return None
    raw = getattr(u, "id", None) or getattr(u, "user_id", None)
    return _safe_uuid(raw)


def _current_admin_role_name() -> str:
    u = _current_user()
    if u is None:
        return "admin"

    role_name = getattr(u, "role_name", None)
    if isinstance(role_name, str) and role_name.strip():
        return role_name.strip().lower()

    try:
        role_int = int(getattr(u, "role", ROLE_ADMIN))
    except Exception:
        role_int = ROLE_ADMIN

    return {1: "admin", 2: "farmer", 3: "customer"}.get(role_int, "admin")


# --------------------------------------------------------------------
# Audit helpers
# --------------------------------------------------------------------
def _audit_admin_view(
    *,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[Any] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    admin_uuid = _current_admin_uuid()
    if admin_uuid is None:
        return

    AuditLogger.log_user_activity(
        user_id=admin_uuid,
        role_name=_current_admin_role_name(),
        action=action,
        target_type=target_type,
        target_id=target_id,
        session_id=_request_session_id(),
        route=request.path,
        http_method=request.method,
        ip_address=_client_ip(),
        user_agent=_user_agent(),
        metadata_json=metadata or {},
    )


def _audit_admin_governance(
    *,
    action: str,
    entity_type: str,
    entity_id: Any,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    admin_uuid = _current_admin_uuid()
    if admin_uuid is None:
        return

    AuditLogger.log_admin_event(
        admin_id=admin_uuid,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        metadata=metadata or {},
    )


# --------------------------------------------------------------------
# Query / serialization helpers
# --------------------------------------------------------------------
def _latest_payment_for_order(order_id: uuid.UUID) -> Optional[Payment]:
    return db.session.execute(
        select(Payment)
        .where(Payment.order_id == order_id)
        .order_by(desc(Payment.updated_at), desc(Payment.created_at), desc(Payment.payment_id))
        .limit(1)
    ).scalar_one_or_none()


def _serialize_admin_order(
    order: Order,
    *,
    include_items: bool,
    include_payments: bool = True,
) -> dict[str, Any]:
    """
    Build an admin-friendly order payload using the shared order serializer plus
    payment enrichment from the payments service.
    """
    buyer_map = build_buyer_map([order])
    payload = serialize_order(
        order,
        include_items=include_items,
        buyer_map=buyer_map,
        farmer_id=None,
    )

    order_uuid = _safe_uuid(getattr(order, "id", None) or getattr(order, "order_id", None))
    if order_uuid is None:
        return payload

    latest_payment = serialize_latest_order_payment(order_uuid)
    payment_summary = build_order_payment_summary(
        order_uuid,
        expected_total=getattr(order, "order_total", None) or getattr(order, "total", None) or 0,
    )

    payload["payment"] = latest_payment
    payload["payment_summary"] = payment_summary
    payload["payment_status"] = payment_summary.get("payment_status")
    payload["payment_method"] = payment_summary.get("payment_method")
    payload["paid_at"] = payment_summary.get("paid_at")
    payload["payments"] = serialize_order_payments(order_uuid) if include_payments else []

    return payload


# ====================================================================
# ROUTES
# ====================================================================
@admin_orders_bp.route("", methods=["GET"])
@require_access_token
def list_orders() -> Response:
    """
    Admin list orders.

    Supported query params:
      status=...
      payment_status=...
      include_items=1
      include_payments=1
      limit=...
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    status = (request.args.get("status") or "").strip().lower()
    payment_status = (request.args.get("payment_status") or "").strip().lower()
    include_items = _bool_qp("include_items", False)
    include_payments = _bool_qp("include_payments", False)
    limit = _int_qp("limit", 300, min_v=1, max_v=1000)

    stmt = (
        select(Order)
        .options(
            selectinload(Order.items),
            selectinload(Order.buyer),
        )
        .order_by(Order.order_date.desc())
        .limit(limit)
    )

    if status:
        stmt = stmt.where(Order.status == status)

    rows = db.session.execute(stmt).scalars().all()

    if payment_status:
        filtered_rows: list[Order] = []
        for order in rows:
            latest_payment = _latest_payment_for_order(order.id)
            latest_status = _safe_str(getattr(latest_payment, "status", None)).strip().lower()
            if latest_status == payment_status:
                filtered_rows.append(order)
        rows = filtered_rows

    payload = [
        _serialize_admin_order(
            order,
            include_items=include_items,
            include_payments=include_payments,
        )
        for order in rows
    ]

    _audit_admin_view(
        action="admin_list_orders",
        target_type="order",
        metadata={
            "status": status,
            "payment_status": payment_status,
            "include_items": include_items,
            "include_payments": include_payments,
            "limit": limit,
            "result_count": len(payload),
        },
    )

    return _json({"success": True, "orders": payload}, 200)


@admin_orders_bp.route("/<uuid:order_id>", methods=["GET"])
@require_access_token
def get_order_detail(order_id: uuid.UUID) -> Response:
    """
    Admin read-only order detail.

    Why this route exists:
      - The admin detail page should not rely on the shared /api/orders/<id>
        serializer path because that path can apply customer/farmer-specific
        slicing rules and extra payment-scope logic.
      - Admin needs a stable, full-order payload with optional payments.
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    include_items = _bool_qp("include_items", True)
    include_payments = _bool_qp("include_payments", True)

    order = db.session.execute(
        select(Order)
        .options(
            selectinload(Order.items),
            selectinload(Order.buyer),
        )
        .where(Order.id == order_id)
    ).scalar_one_or_none()

    if order is None:
        return _json({"success": False, "message": "Order not found"}, 404)

    payload = _serialize_admin_order(
        order,
        include_items=include_items,
        include_payments=include_payments,
    )

    _audit_admin_view(
        action="admin_view_order_detail",
        target_type="order",
        target_id=str(order_id),
        metadata={
            "include_items": include_items,
            "include_payments": include_payments,
        },
    )

    return _json({"success": True, "order": payload}, 200)


@admin_orders_bp.route("/<uuid:order_id>", methods=["PATCH"])
@require_access_token
def update_order(order_id: uuid.UUID) -> Response:
    """
    Admin update order.

    Supported payload fields:
      {
        "status": "pending|completed|cancelled",
        "delivery_status": "pending|processing|dispatched|delivered|cancelled",
        "expected_delivery_date": "<iso or yyyy-mm-dd>",
        "delivered_at": "<iso>",
        "payment_status": "unpaid|paid|pending|failed|refunded",
        "payment_method": "eft|cash|demo|...",
        "payment_reference": "...",
        "mark_paid": true
      }
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        payload = {}

    order = db.session.execute(
        select(Order)
        .options(
            selectinload(Order.items),
            selectinload(Order.buyer),
        )
        .where(Order.id == order_id)
    ).scalar_one_or_none()

    if order is None:
        return _json({"success": False, "message": "Order not found"}, 404)

    admin_uuid = _current_admin_uuid()
    before_order_status = _safe_str(getattr(order, "status", None)).strip().lower()
    before_delivery_status = _safe_str(getattr(order, "delivery_status", None)).strip().lower()

    before_payment = _latest_payment_for_order(order_id)
    before_payment_status = _safe_str(getattr(before_payment, "status", None)).strip().lower()
    before_payment_method = _safe_str(getattr(before_payment, "method", None))
    before_payment_reference = _safe_str(getattr(before_payment, "reference", None))

    governance_events: list[tuple[str, dict[str, Any]]] = []

    if "status" in payload:
        new_status = _safe_str(payload.get("status")).strip().lower()
        if new_status:
            if new_status not in _ALLOWED_ORDER_STATUSES:
                return _json(
                    {
                        "success": False,
                        "message": f"Invalid status. Allowed: {sorted(_ALLOWED_ORDER_STATUSES)}",
                    },
                    400,
                )

            if new_status != before_order_status:
                order.status = new_status
                governance_events.append(
                    (
                        "update_order_status",
                        {
                            "order_id": str(order.id),
                            "before_status": before_order_status,
                            "after_status": new_status,
                        },
                    )
                )

    if "delivery_status" in payload:
        new_delivery_status = _safe_str(payload.get("delivery_status")).strip().lower()
        if new_delivery_status:
            if new_delivery_status not in _ALLOWED_DELIVERY_STATUSES:
                return _json(
                    {
                        "success": False,
                        "message": (
                            f"Invalid delivery_status. Allowed: "
                            f"{sorted(_ALLOWED_DELIVERY_STATUSES)}"
                        ),
                    },
                    400,
                )

            if new_delivery_status != before_delivery_status:
                order.delivery_status = new_delivery_status
                governance_events.append(
                    (
                        "update_order_delivery_status",
                        {
                            "order_id": str(order.id),
                            "before_delivery_status": before_delivery_status,
                            "after_delivery_status": new_delivery_status,
                        },
                    )
                )

    if "expected_delivery_date" in payload:
        parsed = _parse_dt(payload.get("expected_delivery_date"))
        order.expected_delivery_date = parsed

    if "delivered_at" in payload:
        parsed = _parse_dt(payload.get("delivered_at"))
        order.delivered_at = parsed

    if getattr(order, "status", None) == "completed" and getattr(order, "delivered_at", None) is None:
        order.delivered_at = datetime.utcnow()

    payment_status = _safe_str(payload.get("payment_status")).strip().lower()
    payment_method = _safe_str(payload.get("payment_method")).strip() or None
    payment_reference = _safe_str(payload.get("payment_reference")).strip() or None
    mark_paid = bool(payload.get("mark_paid"))

    if mark_paid and not payment_status:
        payment_status = "paid"

    if payment_status:
        if payment_status not in _ALLOWED_PAYMENT_STATUSES:
            return _json(
                {
                    "success": False,
                    "message": f"Invalid payment_status. Allowed: {sorted(_ALLOWED_PAYMENT_STATUSES)}",
                },
                400,
            )

        payment_amount = (
            getattr(order, "order_total", None)
            or getattr(order, "total", None)
            or Decimal("0.00")
        )

        upsert_order_payment(
            order_id=order_id,
            amount=payment_amount,
            status=payment_status,
            method=payment_method or before_payment_method,
            reference=payment_reference or before_payment_reference,
            user_id=getattr(order, "buyer_id", None),
            commit=False,
        )

        governance_events.append(
            (
                "update_order_payment",
                {
                    "order_id": str(order.id),
                    "before_payment_status": before_payment_status or "unpaid",
                    "after_payment_status": payment_status,
                    "before_payment_method": before_payment_method,
                    "after_payment_method": payment_method or before_payment_method,
                    "before_payment_reference": before_payment_reference,
                    "after_payment_reference": payment_reference or before_payment_reference,
                },
            )
        )

    db.session.add(order)
    db.session.commit()

    refreshed = db.session.execute(
        select(Order)
        .options(
            selectinload(Order.items),
            selectinload(Order.buyer),
        )
        .where(Order.id == order_id)
    ).scalar_one()

    response_payload = _serialize_admin_order(
        refreshed,
        include_items=True,
        include_payments=True,
    )

    _audit_admin_view(
        action="admin_update_order",
        target_type="order",
        target_id=str(order_id),
        metadata={
            "updated_status": payload.get("status"),
            "updated_delivery_status": payload.get("delivery_status"),
            "updated_payment_status": payment_status or None,
        },
    )

    for action_name, metadata in governance_events:
        _audit_admin_governance(
            action=action_name,
            entity_type="order",
            entity_id=order_id,
            metadata=metadata,
        )

    return _json(
        {
            "success": True,
            "message": "Order updated successfully",
            "order": response_payload,
            "admin_id": str(admin_uuid) if admin_uuid else None,
        },
        200,
    )