# ============================================================================
# backend/routes/cart.py — Cart API (Multi-item + Decimal Qty Ready)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Customer cart management.
#   CartItems act as a staging area before checkout creates:
#     • Order (header)
#     • OrderItems (line items)
#
# THIS VERSION ADDS:
#   ✅ Settings-driven cart policy from current_app.config
#      - MAX_CART_ITEMS
#      - MAINTENANCE_MODE
#      - READ_ONLY_MODE
#   ✅ Decimal-safe quantities for kg / l / pack style products
#   ✅ Schema-robust Product / CartItem id handling
#   ✅ Frontend-friendly cart payload with policy metadata
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
from flask.globals import current_app, request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import and_, or_
from sqlalchemy.orm import joinedload

from backend.database.db import db
from backend.models.cart_item import CartItem
from backend.models.product import Product
from backend.models.user import User
from backend.security import token_required

cart_bp = Blueprint("cart", __name__)


# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------
def _json(payload: Dict[str, Any], status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _current_user() -> Optional[User]:
    """
    token_required should attach request.current_user.
    This helper keeps routes clean and avoids type checker noise.
    """
    u = getattr(request, "current_user", None)
    return u if isinstance(u, User) else None


def _safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    try:
        text = str(value).strip()
        return text if text else fallback
    except Exception:
        return fallback


def _cfg_bool(name: str, default: bool) -> bool:
    value = current_app.config.get(name, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _cfg_int(name: str, default: int, *, min_value: int, max_value: int) -> int:
    try:
        parsed = int(current_app.config.get(name, default))
    except Exception:
        parsed = default
    return max(min_value, min(max_value, parsed))


def _platform_write_block_message() -> Optional[str]:
    """
    Central guard for write operations.

    GET cart can remain available during maintenance/read-only mode so the UI can
    still render existing cart state, but cart mutations should be blocked.
    """
    if _cfg_bool("MAINTENANCE_MODE", False):
        return _safe_str(
            current_app.config.get("MAINTENANCE_MESSAGE"),
            "Cart updates are temporarily unavailable while the platform is in maintenance mode.",
        )

    if _cfg_bool("READ_ONLY_MODE", False):
        return "Cart updates are temporarily unavailable because the marketplace is in read-only mode."

    return None


def _to_uuid(value: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _to_decimal(value: Any) -> Decimal:
    """
    Parse numeric-like input safely:
      • Accepts int / float / str
      • Returns Decimal(0) on invalid input
    """
    if value is None:
        return Decimal("0")

    raw = str(value).strip()
    if not raw:
        return Decimal("0")

    try:
        return Decimal(raw)
    except (InvalidOperation, ValueError, TypeError):
        return Decimal("0")


def _money(x: Decimal) -> Decimal:
    """Two-decimal rounding for totals and UI summaries."""
    return x.quantize(Decimal("0.01"))


def _cart_item_pk(item: CartItem) -> Optional[uuid.UUID]:
    return _to_uuid(getattr(item, "cart_item_id", None) or getattr(item, "id", None))


def _product_pk(product: Product) -> Optional[uuid.UUID]:
    return _to_uuid(getattr(product, "product_id", None) or getattr(product, "id", None))


def _product_name(product: Product) -> str:
    return _safe_str(getattr(product, "product_name", None) or getattr(product, "name", None), "Unnamed product")


def _resolve_product(product_id: uuid.UUID) -> Optional[Product]:
    """
    Resolve a product robustly across environments where the mapped PK may be
    exposed as product_id, id, or both.
    """
    try:
        product = db.session.get(Product, product_id)  # type: ignore[attr-defined]
        if product is not None:
            return product
    except Exception:
        pass

    clauses: List[Any] = []
    if hasattr(Product, "product_id"):
        clauses.append(getattr(Product, "product_id") == product_id)  # type: ignore[comparison-overlap]
    if hasattr(Product, "id"):
        clauses.append(getattr(Product, "id") == product_id)  # type: ignore[comparison-overlap]

    if not clauses:
        return None

    try:
        return db.session.query(Product).filter(or_(*clauses)).first()  # type: ignore[attr-defined]
    except Exception:
        return None


def _max_cart_items() -> int:
    return _cfg_int("MAX_CART_ITEMS", 50, min_value=1, max_value=500)


def _cart_policy_snapshot() -> Dict[str, Any]:
    """
    Small policy snapshot returned with cart payloads.
    This helps the frontend understand server-side cart policy without requiring
    another roundtrip.
    """
    return {
        "max_cart_items": _max_cart_items(),
        "maintenance": _cfg_bool("MAINTENANCE_MODE", False),
        "read_only_mode": _cfg_bool("READ_ONLY_MODE", False),
    }


def _cart_payload(user_id: uuid.UUID) -> Dict[str, Any]:
    """
    Frontend-friendly cart payload:
      {
        items: [{
          id, product_id, product_name, image_url,
          unit_price, qty, unit, pack_size, pack_unit,
          line_total
        }],
        subtotal, item_count, policy
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
        product: Optional[Product] = getattr(it, "product", None)
        if not product:
            continue

        qty = Decimal(getattr(it, "qty", 0) or 0)
        unit_price = Decimal(getattr(product, "price", 0) or 0)
        line_total = _money(unit_price * qty)
        subtotal += line_total

        out_items.append(
            {
                "id": str(_cart_item_pk(it) or ""),
                "product_id": str(_product_pk(product) or ""),
                "product_name": _product_name(product),
                "image_url": getattr(product, "image_url", None),
                "unit_price": float(unit_price),
                "qty": float(qty),
                "unit": getattr(product, "unit", "each"),
                "pack_size": float(getattr(product, "pack_size", 0) or 0)
                if getattr(product, "pack_size", None) is not None
                else None,
                "pack_unit": getattr(product, "pack_unit", None),
                "line_total": float(line_total),
                "available_stock": float(getattr(product, "quantity", 0) or 0),
                "farmer_id": _safe_str(getattr(product, "user_id", None) or getattr(product, "farmer_id", None)) or None,
            }
        )

    return {
        "items": out_items,
        "subtotal": float(_money(subtotal)),
        "item_count": len(out_items),
        "policy": _cart_policy_snapshot(),
    }


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@cart_bp.get("/", strict_slashes=False)
@token_required
def get_cart() -> Response:
    user = _current_user()
    if not user:
        return _json({"success": False, "message": "Unauthorized"}, 401)

    return _json({"success": True, "cart": _cart_payload(user.id)})


@cart_bp.post("/items", strict_slashes=False)
@token_required
def add_cart_item() -> Response:
    """
    POST /api/cart/items
    Body: { product_id, qty }

    Settings-driven behavior:
      • respects MAX_CART_ITEMS
      • blocks writes during maintenance/read-only mode
    """
    user = _current_user()
    if not user:
        return _json({"success": False, "message": "Unauthorized"}, 401)

    blocked_message = _platform_write_block_message()
    if blocked_message:
        return _json({"success": False, "message": blocked_message}, 409)

    data = request.get_json(silent=True) or {}

    product_id = _to_uuid(data.get("product_id"))
    qty = _to_decimal(data.get("qty", data.get("quantity", 1)))

    if not product_id:
        return _json({"success": False, "message": "product_id is required"}, 400)
    if qty <= 0:
        return _json({"success": False, "message": "qty must be > 0"}, 400)

    product = _resolve_product(product_id)
    if not product:
        return _json({"success": False, "message": "Product not found"}, 404)

    existing: Optional[CartItem] = (
        db.session.query(CartItem)  # type: ignore[attr-defined]
        .filter(and_(CartItem.user_id == user.id, CartItem.product_id == product_id))
        .first()
    )

    if existing is None:
        distinct_count = (
            db.session.query(CartItem)  # type: ignore[attr-defined]
            .filter(CartItem.user_id == user.id)
            .count()
        )
        if distinct_count >= _max_cart_items():
            return _json(
                {
                    "success": False,
                    "message": f"Cart limit reached. Maximum distinct cart items is {_max_cart_items()}.",
                },
                409,
            )

    if existing:
        existing.qty = Decimal(getattr(existing, "qty", 0) or 0) + qty
    else:
        ci = CartItem()
        ci.user_id = user.id
        ci.product_id = product_id
        ci.qty = qty
        db.session.add(ci)  # type: ignore[attr-defined]

    db.session.commit()  # type: ignore[attr-defined]
    return _json({"success": True, "cart": _cart_payload(user.id)}, 201)


@cart_bp.patch("/items/<string:item_id>", strict_slashes=False)
@token_required
def update_cart_item(item_id: str) -> Response:
    """
    PATCH /api/cart/items/:itemId
    Body: { qty }
    If qty <= 0 → removes item.
    """
    user = _current_user()
    if not user:
        return _json({"success": False, "message": "Unauthorized"}, 401)

    blocked_message = _platform_write_block_message()
    if blocked_message:
        return _json({"success": False, "message": blocked_message}, 409)

    item_uuid = _to_uuid(item_id)
    if not item_uuid:
        return _json({"success": False, "message": "Invalid cart item id"}, 400)

    data = request.get_json(silent=True) or {}
    qty = _to_decimal(data.get("qty", data.get("quantity", None)))

    item: Optional[CartItem] = (
        db.session.query(CartItem)  # type: ignore[attr-defined]
        .filter(
            and_(
                or_(
                    getattr(CartItem, "cart_item_id", None) == item_uuid,
                    getattr(CartItem, "id", None) == item_uuid,
                ),
                CartItem.user_id == user.id,
            )
        )
        .first()
    )
    if not item:
        return _json({"success": False, "message": "Cart item not found"}, 404)

    if qty <= 0:
        db.session.delete(item)  # type: ignore[attr-defined]
    else:
        item.qty = qty

    db.session.commit()  # type: ignore[attr-defined]
    return _json({"success": True, "cart": _cart_payload(user.id)})


@cart_bp.delete("/items/<string:item_id>", strict_slashes=False)
@token_required
def delete_cart_item(item_id: str) -> Response:
    user = _current_user()
    if not user:
        return _json({"success": False, "message": "Unauthorized"}, 401)

    blocked_message = _platform_write_block_message()
    if blocked_message:
        return _json({"success": False, "message": blocked_message}, 409)

    item_uuid = _to_uuid(item_id)
    if not item_uuid:
        return _json({"success": False, "message": "Invalid cart item id"}, 400)

    item: Optional[CartItem] = (
        db.session.query(CartItem)  # type: ignore[attr-defined]
        .filter(
            and_(
                or_(
                    getattr(CartItem, "cart_item_id", None) == item_uuid,
                    getattr(CartItem, "id", None) == item_uuid,
                ),
                CartItem.user_id == user.id,
            )
        )
        .first()
    )
    if not item:
        return _json({"success": False, "message": "Cart item not found"}, 404)

    db.session.delete(item)  # type: ignore[attr-defined]
    db.session.commit()  # type: ignore[attr-defined]
    return _json({"success": True, "cart": _cart_payload(user.id)})


@cart_bp.delete("/", strict_slashes=False)
@token_required
def clear_cart() -> Response:
    user = _current_user()
    if not user:
        return _json({"success": False, "message": "Unauthorized"}, 401)

    blocked_message = _platform_write_block_message()
    if blocked_message:
        return _json({"success": False, "message": blocked_message}, 409)

    db.session.query(CartItem).filter(CartItem.user_id == user.id).delete()  # type: ignore[attr-defined]
    db.session.commit()  # type: ignore[attr-defined]
    return _json({"success": True, "cart": _cart_payload(user.id)})
