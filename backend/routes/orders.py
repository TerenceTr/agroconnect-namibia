# ============================================================================
# backend/routes/orders.py — Orders API (Multi-item Orders + C1 Quantities)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Checkout + order history + order detail endpoints.
#
# KEY DESIGN:
#   • "orders"      = header (buyer/status/payment/total/date)
#   • "order_items" = line items (product_id + decimal quantity + price totals)
#
# WHY THIS VERSION FIXES YOUR VS CODE ERRORS:
#   • Pyright-friendly Flask imports (typed submodules)
#   • No ORM constructor kwargs (avoids "No parameter named ...")
#   • Uses Order.id (mapped to DB column orders.order_id)
#   • Assigns UUIDs (not strings) into UUID-typed mapped columns
#   • Uses tz-naive datetimes for tz-naive DB columns
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import and_
from sqlalchemy.orm import selectinload

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User
from backend.security import token_required

try:
    from backend.models.cart_item import CartItem  # optional table
except Exception:  # pragma: no cover
    CartItem = None  # type: ignore[assignment]


orders_bp = Blueprint("orders", __name__)


def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _current_user() -> Optional[User]:
    """
    token_required() should inject request.current_user.
    Access via getattr() so Pyright doesn't complain about unknown attributes.
    """
    u = getattr(request, "current_user", None)
    return u if isinstance(u, User) else None


def _to_uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _to_decimal(value: Any) -> Decimal:
    """
    Decimal parser that safely accepts int/float/str.
    Returns Decimal('0') on invalid input.
    """
    if value is None:
        return Decimal("0")
    raw = str(value).strip()
    if not raw:
        return Decimal("0")
    try:
        return Decimal(raw)
    except (InvalidOperation, ValueError):
        return Decimal("0")


def _money(x: Decimal) -> Decimal:
    """Quantize money to cents (DB is numeric(10,2) or numeric(12,2))."""
    return x.quantize(Decimal("0.01"))


def _role_is(user: User, role_const: int) -> bool:
    """DB stores role as int (1=admin,2=farmer,3=customer)."""
    try:
        return int(getattr(user, "role", 0)) == int(role_const)
    except Exception:
        return False


def _order_query_for_user(user: User):
    """
    Visibility rules:
      • Admin: all orders
      • Customer: orders they placed
      • Farmer: orders that include at least one of their products (via order_items)
    """
    q = db.session.query(Order).options(selectinload(Order.items))  # type: ignore[attr-defined]

    if _role_is(user, ROLE_ADMIN):
        return q

    if _role_is(user, ROLE_CUSTOMER):
        return q.filter(Order.buyer_id == user.id)

    if _role_is(user, ROLE_FARMER):
        return (
            q.join(OrderItem, OrderItem.order_id == Order.id)
            .join(Product, Product.product_id == OrderItem.product_id)
            .filter(Product.farmer_id == user.id)
            .distinct()
        )

    return q.filter(Order.buyer_id == user.id)


@orders_bp.get("/", strict_slashes=False)
@token_required
def list_orders() -> Response:
    """
    GET /api/orders
    Returns header-only order serialization (items omitted) for list pages.
    """
    user = _current_user()
    if user is None:
        return _json({"success": False, "message": "Unauthorized"}, 401)

    q = _order_query_for_user(user)

    status = (request.args.get("status") or "").strip()
    payment_status = (request.args.get("payment_status") or "").strip()
    if status:
        q = q.filter(Order.status == status)
    if payment_status:
        q = q.filter(Order.payment_status == payment_status)

    orders: List[Order] = q.order_by(Order.order_date.desc()).limit(200).all()
    return _json({"success": True, "orders": [o.to_dict(include_items=False) for o in orders]}, 200)


@orders_bp.get("/<string:order_id>", strict_slashes=False)
@token_required
def get_order(order_id: str) -> Response:
    """
    GET /api/orders/<order_id>
    Returns order + line items if user has access.
    """
    user = _current_user()
    if user is None:
        return _json({"success": False, "message": "Unauthorized"}, 401)

    oid = _to_uuid(order_id)
    if oid is None:
        return _json({"success": False, "message": "Invalid order id"}, 400)

    order: Optional[Order] = (
        db.session.query(Order)  # type: ignore[attr-defined]
        .options(selectinload(Order.items).selectinload(OrderItem.product))
        .filter(Order.id == oid)
        .first()
    )
    if order is None:
        return _json({"success": False, "message": "Order not found"}, 404)

    # Visibility rules
    if not _role_is(user, ROLE_ADMIN):
        # Customer can only see their own
        if _role_is(user, ROLE_CUSTOMER) and order.buyer_id != user.id:
            return _json({"success": False, "message": "Forbidden"}, 403)

        # Farmer can only see if at least one line item is their product
        if _role_is(user, ROLE_FARMER):
            has_any = (
                db.session.query(OrderItem)  # type: ignore[attr-defined]
                .join(Product, Product.product_id == OrderItem.product_id)
                .filter(and_(OrderItem.order_id == order.id, Product.farmer_id == user.id))
                .first()
            )
            if not has_any:
                return _json({"success": False, "message": "Forbidden"}, 403)

    return _json({"success": True, "order": order.to_dict(include_items=True)}, 200)


@orders_bp.post("/", strict_slashes=False)
@token_required
def create_order() -> Response:
    """
    POST /api/orders

    Body:
      {
        "items": [
          {"product_id": "...", "qty": 2.5},
          {"product_id": "...", "quantity": 1}
        ],
        "payment_method": "eft"   # optional (stored as payment_reference)
      }

    Creates:
      • Order header
      • OrderItems
      • Decrements Product.quantity (decimal-safe)
      • Optionally clears CartItem table (if present)
    """
    user = _current_user()
    if user is None:
        return _json({"success": False, "message": "Unauthorized"}, 401)

    if not (_role_is(user, ROLE_CUSTOMER) or _role_is(user, ROLE_ADMIN)):
        return _json({"success": False, "message": "Only customers can place orders"}, 403)

    payload = request.get_json(silent=True) or {}
    raw_items = payload.get("items") or []
    if not isinstance(raw_items, list) or not raw_items:
        return _json({"success": False, "message": "items[] is required"}, 400)

    # Parse items, aggregate duplicate product_ids
    aggregated: Dict[uuid.UUID, Decimal] = {}
    for it in raw_items:
        if not isinstance(it, dict):
            continue
        pid = _to_uuid(it.get("product_id"))
        qty = _to_decimal(it.get("qty", it.get("quantity", 0)))
        if pid and qty > 0:
            aggregated[pid] = aggregated.get(pid, Decimal("0")) + qty

    if not aggregated:
        return _json({"success": False, "message": "No valid items"}, 400)

    product_ids = list(aggregated.keys())

    # Lock product rows to prevent overselling under concurrency
    products: List[Product] = (
        db.session.query(Product)  # type: ignore[attr-defined]
        .filter(Product.product_id.in_(product_ids))
        .with_for_update()
        .all()
    )
    product_map: Dict[uuid.UUID, Product] = {p.product_id: p for p in products}

    missing = [str(pid) for pid in product_ids if pid not in product_map]
    if missing:
        return _json({"success": False, "message": f"Products not found: {', '.join(missing)}"}, 404)

    # Stock check
    for pid, qty in aggregated.items():
        p = product_map[pid]
        available = p.quantity if p.quantity is not None else Decimal("0")
        if available < qty:
            return _json({"success": False, "message": f"Insufficient stock for {p.product_name}"}, 400)

    # Create Order header (NO kwargs -> Pyright clean)
    # DB uses tz-naive timestamps, so use utcnow() without tzinfo.
    now = datetime.utcnow()

    order = Order()
    order.buyer_id = user.id
    order.status = "pending"
    order.payment_status = "unpaid"
    order.order_date = now

    payment_method = str(payload.get("payment_method") or "").strip()
    order.payment_reference = payment_method or None

    order.order_total = Decimal("0.00")

    db.session.add(order)  # type: ignore[attr-defined]
    db.session.flush()  # type: ignore[attr-defined]  # assigns order.id

    total = Decimal("0.00")

    # Create OrderItems + decrement stock
    for pid, qty in aggregated.items():
        p = product_map[pid]
        unit_price = p.price if p.price is not None else Decimal("0")
        line_total = _money(unit_price * qty)

        oi = OrderItem()
        oi.order_id = order.id          # ✅ UUID -> UUID (type-safe)
        oi.product_id = pid
        oi.quantity = qty
        oi.unit_price = unit_price
        oi.line_total = line_total

        # Snapshot C1 unit metadata for analytics/historical accuracy
        oi.unit = str(getattr(p, "unit", "each") or "each")
        if oi.unit == "pack":
            oi.pack_size = getattr(p, "pack_size", None)
            oi.pack_unit = getattr(p, "pack_unit", None)
        else:
            oi.pack_size = None
            oi.pack_unit = None

        db.session.add(oi)  # type: ignore[attr-defined]

        # Deduct stock (decimal-safe)
        current_qty = p.quantity if p.quantity is not None else Decimal("0")
        p.quantity = current_qty - qty
        total += line_total

    order.order_total = _money(total)

    # Optional: clear cart after checkout (if your schema includes it)
    if CartItem is not None:
        try:
            db.session.query(CartItem).filter(CartItem.user_id == user.id).delete()  # type: ignore[attr-defined]
        except Exception:
            pass

    db.session.commit()  # type: ignore[attr-defined]

    # Reload order with items for response
    refreshed: Optional[Order] = (
        db.session.query(Order)  # type: ignore[attr-defined]
        .options(selectinload(Order.items).selectinload(OrderItem.product))
        .filter(Order.id == order.id)
        .first()
    )

    return _json({"success": True, "order": (refreshed or order).to_dict(include_items=True)}, 201)
