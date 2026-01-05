# ============================================================================
# backend/routes/admin.py — Admin Overview API (JWT + ADMIN ONLY)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin dashboard "overview" endpoint.
#   Provides KPI counts + recent lists (users/products/orders) in a UI-friendly
#   format. Safe for multi-item orders (Order -> items -> product).
#
# MAIN FIX (YOUR REQUEST):
#   Pylance error:
#     "Cannot access attribute 'to_dict' for class 'Product'"
#   is removed by:
#     • serializing products via a safe helper that calls to_dict() if present,
#       otherwise falls back to attribute-based serialization.
#
# ROUTE (registered with url_prefix="/api/admin"):
#   GET /api/admin/overview
# ============================================================================

from __future__ import annotations

from typing import Any, Dict, List

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, User
from backend.utils.presence_store import is_online, online_user_ids
from backend.utils.require_auth import require_access_token

admin_bp = Blueprint("admin", __name__)


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def _json_error(msg: str, status: int) -> Any:
    resp = jsonify({"success": False, "message": msg})
    resp.status_code = status
    return resp


def _require_admin() -> User | Any:
    """Return User if admin, else a JSON error response."""
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)
    if getattr(user, "role", None) != ROLE_ADMIN:
        return _json_error("Forbidden", 403)
    return user


def _order_product_summary(order: Order) -> str:
    """
    Dashboard-friendly single string for a multi-item order.

    Example:
      • "Tomatoes" (1 item)
      • "Tomatoes +2 more" (3 items)
    """
    items = getattr(order, "items", None) or []
    if not items:
        return "—"

    first = items[0]
    prod = getattr(first, "product", None)
    first_name = getattr(prod, "product_name", None) or getattr(prod, "name", None) or "Item"

    extra = max(len(items) - 1, 0)
    return f"{first_name} +{extra} more" if extra else str(first_name)


def _product_out(p: Any) -> Dict[str, Any]:
    """
    ✅ Fixes Pylance:
      We do NOT directly call p.to_dict() as a statically-known method.
      Instead, we call it dynamically if present.

    Also provides a safe fallback shape if to_dict() isn't available for any reason.
    """
    td = getattr(p, "to_dict", None)
    if callable(td):
        try:
            out = td()
            if isinstance(out, dict):
                return out
        except Exception:
            pass

    # Fallback (should rarely be used if Product.to_dict exists)
    return {
        "id": str(getattr(p, "product_id", getattr(p, "id", ""))),
        "name": getattr(p, "product_name", getattr(p, "name", "")),
        "status": getattr(p, "status", None),
        "price": float(getattr(p, "price", 0) or 0),
        "quantity": float(getattr(p, "quantity", getattr(p, "stock", 0)) or 0),
        "created_at": getattr(getattr(p, "created_at", None), "isoformat", lambda: None)(),
    }


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@admin_bp.get("/overview")
@require_access_token
def overview() -> Any:
    """
    Admin dashboard overview data.

    Returns:
      {
        success: true,
        kpis: {...},
        recent: { users: [...], products: [...], orders: [...] }
      }
    """
    guard = _require_admin()
    if not isinstance(guard, User):
        return guard

    # -----------------------------
    # KPI counts (fast aggregates)
    # -----------------------------
    users_total = db.session.scalar(select(func.count(User.id))) or 0
    products_total = db.session.scalar(select(func.count(Product.product_id))) or 0
    orders_total = db.session.scalar(select(func.count(Order.id))) or 0

    products_available = (
        db.session.scalar(
            select(func.count(Product.product_id)).where(
                (Product.status == "available") & (Product.quantity > 0)
            )
        )
        or 0
    )

    orders_pending = db.session.scalar(select(func.count(Order.id)).where(Order.status == "pending")) or 0

    # Online count from presence store (last-seen threshold)
    users_online = len(online_user_ids(threshold_seconds=300))

    # -----------------------------
    # Recent lists (eager load to avoid N+1)
    # -----------------------------
    recent_users: List[User] = db.session.scalars(
        select(User).order_by(User.created_at.desc()).limit(8)
    ).all()

    recent_products: List[Product] = db.session.scalars(
        select(Product)
        .options(selectinload(Product.farmer))
        .order_by(Product.created_at.desc())
        .limit(8)
    ).all()

    # Multi-item orders: Order -> items -> product
    recent_orders: List[Order] = db.session.scalars(
        select(Order)
        .options(
            selectinload(Order.buyer),
            selectinload(Order.items).selectinload(OrderItem.product),
        )
        .order_by(Order.order_date.desc())
        .limit(8)
    ).all()

    # Users output: enrich with online flag
    users_out: List[Dict[str, Any]] = []
    for u in recent_users:
        d = u.to_dict()
        d["online"] = bool(is_online(u.id, threshold_seconds=300))
        users_out.append(d)

    # Products output: ✅ uses helper to avoid "Product.to_dict unknown"
    products_out: List[Dict[str, Any]] = [_product_out(p) for p in recent_products]

    # Orders output: enrich with buyer_name + product summary + item_count
    orders_out: List[Dict[str, Any]] = []
    for o in recent_orders:
        od = o.to_dict()

        buyer = getattr(o, "buyer", None)
        buyer_name = getattr(buyer, "full_name", None) or "Buyer"
        od.setdefault("buyer_name", buyer_name)

        od["product_name"] = _order_product_summary(o)
        od["item_count"] = len(getattr(o, "items", None) or [])

        orders_out.append(od)

    return jsonify(
        {
            "success": True,
            "kpis": {
                "users_total": int(users_total),
                "users_online": int(users_online),
                "products_total": int(products_total),
                "products_available": int(products_available),
                "orders_total": int(orders_total),
                "orders_pending": int(orders_pending),
            },
            "recent": {
                "users": users_out,
                "products": products_out,
                "orders": orders_out,
            },
        }
    )
