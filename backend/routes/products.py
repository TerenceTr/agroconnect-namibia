# ====================================================================
# backend/routes/products.py — Product Management API (JWT-PROTECTED)
# ====================================================================
# FILE ROLE:
#   • Public product listing + product detail
#   • Public convenience feeds: /new and /top-selling (placeholder)
#   • Protected create/update/delete (Farmer/Admin)
#   • Supports JSON + multipart/form-data (image upload)
#
# WHY THIS FILE IS UPDATED:
#   ✅ Fix Pyright/Pylance error: Product.quantity is Decimal, but code assigned int
#   ✅ C1 requires decimal stock quantities (kg/l can be fractional)
#   ✅ C1 adds unit + optional pack_size/pack_unit (when unit == "pack")
#
# PREFIX RULE:
#   • DO NOT hardcode "/api" here.
#   • Registry registers this blueprint at: /api/products
# ====================================================================

from __future__ import annotations

from decimal import Decimal, InvalidOperation
from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import or_, select

from backend.database.db import db
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_FARMER, User
from backend.utils.require_auth import require_access_token
from backend.utils.upload_utils import default_image_url, save_image

products_bp = Blueprint("products", __name__)

# C1 allowed units (must match Product model CHECK constraint)
_ALLOWED_UNITS = {"kg", "g", "l", "ml", "each", "pack"}
_ALLOWED_PACK_UNITS = {"kg", "g", "l", "ml", "each"}


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def _json_error(message: str, status: int) -> Any:
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


def _to_uuid(value: Any) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except Exception:
        return None


def _to_int(value: Any, default: int) -> int:
    try:
        raw = str(value).strip()
        if not raw:
            return default
        return int(raw)
    except Exception:
        return default


def _to_decimal(value: Any, default: Decimal) -> Decimal:
    """
    Safe Decimal parser for money/quantities.
    Accepts numeric or string input from JSON/form-data.
    """
    try:
        raw = str(value).strip()
        if not raw:
            return default
        return Decimal(raw)
    except (InvalidOperation, ValueError):
        return default


def _to_qty_decimal(value: Any, default: Decimal) -> Decimal:
    """
    Quantity parser normalized to 3dp for Numeric(12,3).
    """
    d = _to_decimal(value, default)
    try:
        return d.quantize(Decimal("0.001"))
    except Exception:
        return default


def _to_money_decimal(value: Any, default: Decimal) -> Decimal:
    """
    Money parser normalized to 2dp for Numeric(12,2).
    """
    d = _to_decimal(value, default)
    try:
        return d.quantize(Decimal("0.01"))
    except Exception:
        return default


def _clean_unit(value: Any, default: str = "each") -> str:
    u = str(value or "").strip().lower() or default
    return u


def _payload() -> dict[str, Any]:
    """
    Accept BOTH JSON and multipart/form-data.
      • JSON requests: request.get_json(silent=True)
      • Multipart:     request.form
    """
    js = request.get_json(silent=True)
    if isinstance(js, dict):
        return js
    return dict(request.form or {})


def _apply_c1_unit_fields(product: Product, data: dict[str, Any]) -> Optional[Any]:
    """
    Apply C1 fields (unit, pack_size, pack_unit) safely.

    Rules:
      • unit must be one of: kg,g,l,ml,each,pack
      • if unit == "pack":
          pack_size must be > 0
          pack_unit must be in kg,g,l,ml,each
      • else:
          pack_size/pack_unit cleared to None
    """
    unit = _clean_unit(data.get("unit", getattr(product, "unit", "each")), default="each")

    if unit not in _ALLOWED_UNITS:
        return _json_error(f"Invalid unit. Allowed: {sorted(_ALLOWED_UNITS)}", 400)

    product.unit = unit  # type: ignore[assignment]

    if unit == "pack":
        pack_size = _to_qty_decimal(data.get("pack_size"), Decimal("0.000"))
        pack_unit = _clean_unit(data.get("pack_unit"), default="").lower() or ""

        if pack_size <= 0:
            return _json_error("pack_size must be > 0 when unit='pack'", 400)

        if pack_unit not in _ALLOWED_PACK_UNITS:
            return _json_error(f"pack_unit must be one of {sorted(_ALLOWED_PACK_UNITS)}", 400)

        product.pack_size = pack_size  # Decimal or None
        product.pack_unit = pack_unit
    else:
        # Not a pack product → clear pack fields
        product.pack_size = None
        product.pack_unit = None

    return None


# --------------------------------------------------------------------
# Public routes
# --------------------------------------------------------------------
@products_bp.get("/", strict_slashes=False)
def list_products() -> Any:
    """
    Public list (newest first).

    Optional filters:
      • q        (search in product_name/description/category)
      • category
      • status
    """
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    status = (request.args.get("status") or "").strip()

    stmt = select(Product).order_by(Product.created_at.desc())

    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                Product.product_name.ilike(like),
                Product.description.ilike(like),
                Product.category.ilike(like),
            )
        )

    if category:
        stmt = stmt.where(Product.category == category)

    if status:
        stmt = stmt.where(Product.status == status)

    products = db.session.scalars(stmt).all()  # type: ignore[attr-defined]
    return jsonify([p.to_dict() for p in products])


@products_bp.get("/new", strict_slashes=False)
def list_new_products() -> Any:
    """Public: latest N products. GET /api/products/new?limit=6"""
    limit = max(1, _to_int(request.args.get("limit", 6), 6))
    stmt = select(Product).order_by(Product.created_at.desc()).limit(limit)
    products = db.session.scalars(stmt).all()  # type: ignore[attr-defined]
    return jsonify([p.to_dict() for p in products])


@products_bp.get("/top-selling", strict_slashes=False)
def list_top_selling() -> Any:
    """
    Public placeholder:
      Replace with real aggregation when you have order rollups.
      For now: return newest products as a safe fallback.
    """
    limit = max(1, _to_int(request.args.get("limit", 6), 6))
    stmt = select(Product).order_by(Product.created_at.desc()).limit(limit)
    products = db.session.scalars(stmt).all()  # type: ignore[attr-defined]
    return jsonify([p.to_dict() for p in products])


@products_bp.get("/<string:product_id>", strict_slashes=False)
def get_product(product_id: str) -> Any:
    """Public product detail."""
    pid = _to_uuid(product_id)
    product = db.session.get(Product, pid) if pid else None  # type: ignore[attr-defined]
    if not product:
        return _json_error("Product not found", 404)
    return jsonify(product.to_dict())


# --------------------------------------------------------------------
# Protected routes (Farmer/Admin)
# --------------------------------------------------------------------
@products_bp.post("/", strict_slashes=False)
@require_access_token
def create_product() -> Any:
    """
    Create product (Farmer/Admin).
    Supports JSON + multipart (image upload).
    """
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    if user.role not in (ROLE_FARMER, ROLE_ADMIN):
        return _json_error("Permission denied", 403)

    data = _payload()
    name = (data.get("product_name") or "").strip()
    if not name:
        return _json_error("product_name is required", 400)

    # Image optional (never crash creation due to storage issues)
    try:
        image_url = save_image(request.files.get("image"), folder="products") or default_image_url()
    except Exception:
        image_url = default_image_url()

    # ✅ C1: quantity is Decimal (Numeric(12,3)), not int
    qty = _to_qty_decimal(data.get("quantity"), Decimal("0.000"))
    if qty < 0:
        return _json_error("quantity must be >= 0", 400)

    product = Product()
    product.product_name = name
    product.description = (data.get("description") or None)
    product.category = (data.get("category") or None)

    # Money (2dp)
    product.price = _to_money_decimal(data.get("price"), Decimal("0.00"))

    # Stock (3dp)
    product.quantity = qty

    product.image_url = image_url

    # In Product model: farmer_id maps DB user_id
    product.farmer_id = user.id

    # C1 fields (unit/pack)
    err = _apply_c1_unit_fields(product, data)
    if err:
        return err

    # New products typically require admin approval
    product.status = "pending"

    db.session.add(product)  # type: ignore[attr-defined]
    db.session.commit()  # type: ignore[attr-defined]

    resp = jsonify(product.to_dict())
    resp.status_code = 201
    return resp


@products_bp.put("/<string:product_id>", strict_slashes=False)
@require_access_token
def update_product(product_id: str) -> Any:
    """Update product (Owner/Admin). Supports JSON + multipart."""
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    pid = _to_uuid(product_id)
    product = db.session.get(Product, pid) if pid else None  # type: ignore[attr-defined]
    if not product:
        return _json_error("Product not found", 404)

    if user.role != ROLE_ADMIN and product.farmer_id != user.id:
        return _json_error("You do not own this product", 403)

    data = _payload()

    if "product_name" in data:
        product.product_name = (data.get("product_name") or "").strip()
    if "description" in data:
        product.description = data.get("description") or None
    if "category" in data:
        product.category = data.get("category") or None
    if "price" in data:
        product.price = _to_money_decimal(data.get("price"), Decimal(str(product.price or "0.00")))

    # ✅ C1: quantity stays Decimal (3dp)
    if "quantity" in data:
        qty = _to_qty_decimal(data.get("quantity"), Decimal(str(product.quantity or "0.000")))
        if qty < 0:
            return _json_error("quantity must be >= 0", 400)
        product.quantity = qty

    # C1 fields (unit/pack) if provided
    if "unit" in data or "pack_size" in data or "pack_unit" in data:
        err = _apply_c1_unit_fields(product, data)
        if err:
            return err

    # Optional image replace
    try:
        new_url = save_image(request.files.get("image"), folder="products")
        if new_url:
            product.image_url = new_url
    except Exception:
        # Ignore image errors on update (don’t block edits)
        pass

    db.session.commit()  # type: ignore[attr-defined]
    return jsonify(product.to_dict())


@products_bp.delete("/<string:product_id>", strict_slashes=False)
@require_access_token
def delete_product(product_id: str) -> Any:
    """Delete product (Owner/Admin)."""
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    pid = _to_uuid(product_id)
    product = db.session.get(Product, pid) if pid else None  # type: ignore[attr-defined]
    if not product:
        return _json_error("Product not found", 404)

    if user.role != ROLE_ADMIN and product.farmer_id != user.id:
        return _json_error("You do not own this product", 403)

    db.session.delete(product)  # type: ignore[attr-defined]
    db.session.commit()  # type: ignore[attr-defined]
    return jsonify({"success": True, "message": "Product deleted"})
