# ============================================================================
# backend/routes/cart.py — Cart API (Multi-item + Decimal Qty Ready)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Customer cart management.
#   CartItems act as a staging area before checkout creates:
#     • Order (header)
#     • OrderItems (line items)
#
# WHY THIS FILE IS UPDATED:
#   • Fix Pyright "unknown import symbol" errors by importing Flask symbols from
#     typed submodules instead of flask top-level exports.
#   • Keep qty Decimal-safe for C1 (kg/l can be fractional).
#
# ROUTES:
#   GET    /api/cart
#   POST   /api/cart/items
#   PATCH  /api/cart/items/<item_id>
#   DELETE /api/cart/items/<item_id>
#   DELETE /api/cart
# ============================================================================

from __future__ import annotations

import uuid
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import and_
from sqlalchemy.orm import joinedload

from backend.database.db import db
from backend.models.cart_item import CartItem
from backend.models.product import Product
from backend.models.user import User
from backend.security import token_required

cart_bp = Blueprint("cart", __name__)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _current_user() -> User | None:
    """
    token_required should attach request.current_user.
    This helper keeps routes clean + avoids type checker noise.
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
    Parse numeric-like input safely:
      • Accepts int/float/str
      • Returns Decimal(0) on invalid
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
    """2dp money rounding for totals."""
    return x.quantize(Decimal("0.01"))


def _cart_payload(user_id: uuid.UUID) -> Dict[str, Any]:
    """
    Frontend-friendly cart payload:
      {
        items: [{
          id, product_id, product_name, image_url,
          unit_price, qty, unit, pack_size, pack_unit,
          line_total
        }],
        subtotal, item_count
      }
    """
    items: List[CartItem] = (
        db.session.query(CartItem)  # type: ignore[attr-defined]
        .options(joinedload(CartItem.product))
        .filter(CartItem.user_id == user_id)
        .order_by(CartItem.created_at.desc())
        .all()
    )

    out_items: List[Dict[str, Any]] = []
    subtotal = Decimal("0")

    for it in items:
        p: Optional[Product] = getattr(it, "product", None)
        if not p:
            continue

        qty = Decimal(it.qty or 0)
        unit_price = Decimal(getattr(p, "price", 0) or 0)
        line_total = _money(unit_price * qty)
        subtotal += line_total

        out_items.append(
            {
                "id": str(it.id),
                "product_id": str(p.id),
                "product_name": getattr(p, "product_name", None) or getattr(p, "name", None),
                "image_url": getattr(p, "image_url", None),
                "unit_price": float(unit_price),
                "qty": float(qty),
                "unit": getattr(p, "unit", "each"),
                "pack_size": float(getattr(p, "pack_size", 0) or 0)
                if getattr(p, "pack_size", None) is not None
                else None,
                "pack_unit": getattr(p, "pack_unit", None),
                "line_total": float(line_total),
            }
        )

    return {
        "items": out_items,
        "subtotal": float(_money(subtotal)),
        "item_count": len(out_items),
    }


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@cart_bp.get("/", strict_slashes=False)
@token_required
def get_cart() -> Any:
    user = _current_user()
    if not user:
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    return jsonify({"success": True, "cart": _cart_payload(user.id)})


@cart_bp.post("/items", strict_slashes=False)
@token_required
def add_cart_item() -> Any:
    """
    POST /api/cart/items
    Body: { product_id, qty }
    """
    user = _current_user()
    if not user:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}

    product_id = _to_uuid(data.get("product_id"))
    qty = _to_decimal(data.get("qty", data.get("quantity", 1)))

    if not product_id:
        return jsonify({"success": False, "message": "product_id is required"}), 400
    if qty <= 0:
        return jsonify({"success": False, "message": "qty must be > 0"}), 400

    product: Optional[Product] = db.session.get(Product, product_id)  # type: ignore[attr-defined]
    if not product:
        return jsonify({"success": False, "message": "Product not found"}), 404

    existing: Optional[CartItem] = (
        db.session.query(CartItem)  # type: ignore[attr-defined]
        .filter(and_(CartItem.user_id == user.id, CartItem.product_id == product_id))
        .first()
    )

    if existing:
        existing.qty = Decimal(existing.qty or 0) + qty
    else:
        ci = CartItem()
        ci.user_id = user.id
        ci.product_id = product_id
        ci.qty = qty
        db.session.add(ci)  # type: ignore[attr-defined]

    db.session.commit()  # type: ignore[attr-defined]
    return jsonify({"success": True, "cart": _cart_payload(user.id)}), 201


@cart_bp.patch("/items/<string:item_id>", strict_slashes=False)
@token_required
def update_cart_item(item_id: str) -> Any:
    """
    PATCH /api/cart/items/:itemId
    Body: { qty }
    If qty <= 0 → removes item
    """
    user = _current_user()
    if not user:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    item_uuid = _to_uuid(item_id)
    if not item_uuid:
        return jsonify({"success": False, "message": "Invalid cart item id"}), 400

    data = request.get_json(silent=True) or {}
    qty = _to_decimal(data.get("qty", data.get("quantity", None)))

    item: Optional[CartItem] = (
        db.session.query(CartItem)  # type: ignore[attr-defined]
        .filter(and_(CartItem.id == item_uuid, CartItem.user_id == user.id))
        .first()
    )
    if not item:
        return jsonify({"success": False, "message": "Cart item not found"}), 404

    if qty <= 0:
        db.session.delete(item)  # type: ignore[attr-defined]
    else:
        item.qty = qty

    db.session.commit()  # type: ignore[attr-defined]
    return jsonify({"success": True, "cart": _cart_payload(user.id)})


@cart_bp.delete("/items/<string:item_id>", strict_slashes=False)
@token_required
def delete_cart_item(item_id: str) -> Any:
    user = _current_user()
    if not user:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    item_uuid = _to_uuid(item_id)
    if not item_uuid:
        return jsonify({"success": False, "message": "Invalid cart item id"}), 400

    item: Optional[CartItem] = (
        db.session.query(CartItem)  # type: ignore[attr-defined]
        .filter(and_(CartItem.id == item_uuid, CartItem.user_id == user.id))
        .first()
    )
    if not item:
        return jsonify({"success": False, "message": "Cart item not found"}), 404

    db.session.delete(item)  # type: ignore[attr-defined]
    db.session.commit()  # type: ignore[attr-defined]
    return jsonify({"success": True, "cart": _cart_payload(user.id)})


@cart_bp.delete("/", strict_slashes=False)
@token_required
def clear_cart() -> Any:
    user = _current_user()
    if not user:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    db.session.query(CartItem).filter(CartItem.user_id == user.id).delete()  # type: ignore[attr-defined]
    db.session.commit()  # type: ignore[attr-defined]
    return jsonify({"success": True, "cart": _cart_payload(user.id)})
