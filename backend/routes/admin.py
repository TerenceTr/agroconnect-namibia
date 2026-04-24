# ============================================================================
# backend/routes/admin.py — Admin Overview API (JWT + ADMIN ONLY)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin dashboard "overview" endpoint (fallback for UI).
#   Provides KPI counts + recent lists (users/products/orders) in a UI-friendly
#   format. Safe for multi-item orders (Order -> items -> product).
#
# ROUTE (registered with url_prefix="/api/admin"):
#   GET /api/admin/overview
#
# IMPORTANT:
#   Presence storage was unified under backend/services/presence_store.py
#   to avoid duplicate implementations.
#
# THIS VERSION FIXES:
#   ✅ Pyright error: no direct `Order.to_dict(...)` call anymore
#   ✅ Safe serialization helpers for User / Product / Order
#   ✅ Better resilience across model/schema variations
# ============================================================================
from __future__ import annotations

from typing import Any, Dict, List, Optional

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, User
from backend.services.presence_store import is_online as presence_is_online
from backend.services.presence_store import snapshot as presence_snapshot
from backend.utils.require_auth import require_access_token

admin_bp = Blueprint("admin", __name__)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _json_error(msg: str, status: int) -> Response:
    resp = jsonify({"success": False, "message": msg})
    resp.status_code = status
    return resp


def _require_admin() -> User | Response:
    """
    Return the authenticated admin User or a typed JSON error response.
    """
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    if getattr(user, "role", None) != ROLE_ADMIN:
        return _json_error("Forbidden", 403)

    return user


def _safe_str(value: Any, default: str = "") -> str:
    try:
        text_value = str(value).strip()
        return text_value or default
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value or 0)
    except Exception:
        return default


def _iso(value: Any) -> Optional[str]:
    try:
        return value.isoformat() if value is not None else None
    except Exception:
        return None


def _order_pk_col() -> Any:
    """
    Resolve the most likely primary-key column on Order.
    Supports codebases that use either `order_id` or `id`.
    """
    return getattr(Order, "order_id", None) or getattr(Order, "id", None)


def _order_date_col() -> Any:
    """
    Resolve the best available order timestamp column.
    """
    return getattr(Order, "order_date", None) or getattr(Order, "created_at", None)


def _product_out(p: Any) -> Dict[str, Any]:
    """
    Serialize Product safely (to_dict if available, else fallback fields).
    """
    td = getattr(p, "to_dict", None)
    if callable(td):
        try:
            out = td()
            if isinstance(out, dict):
                return out
        except Exception:
            pass

    return {
        "id": str(getattr(p, "product_id", getattr(p, "id", ""))),
        "name": getattr(p, "product_name", getattr(p, "name", "")),
        "status": getattr(p, "status", None),
        "price": _safe_float(getattr(p, "price", 0)),
        "quantity": _safe_float(getattr(p, "quantity", getattr(p, "stock", 0))),
        "created_at": _iso(getattr(p, "created_at", None)),
    }


def _user_out(u: Any) -> Dict[str, Any]:
    """
    Serialize User safely (to_dict if available, else fallback fields).
    """
    td = getattr(u, "to_dict", None)
    if callable(td):
        try:
            out = td()
            if isinstance(out, dict):
                return out
        except Exception:
            pass

    return {
        "id": str(getattr(u, "id", getattr(u, "user_id", ""))),
        "full_name": getattr(u, "full_name", getattr(u, "name", "")),
        "email": getattr(u, "email", None),
        "phone": getattr(u, "phone", None),
        "role": getattr(u, "role", None),
        "created_at": _iso(getattr(u, "created_at", None)),
        "updated_at": _iso(getattr(u, "updated_at", None)),
        "is_active": bool(getattr(u, "is_active", True)),
    }


def _order_product_summary(order: Order) -> str:
    """
    Dashboard-friendly single string for a multi-item order.
    """
    items = getattr(order, "items", None) or []
    if not items:
        return "—"

    first = items[0]
    prod = getattr(first, "product", None)
    first_name = (
        getattr(prod, "product_name", None)
        or getattr(prod, "name", None)
        or "Item"
    )

    extra = max(len(items) - 1, 0)
    return f"{first_name} +{extra} more" if extra else str(first_name)


def _order_out(order: Any) -> Dict[str, Any]:
    """
    Serialize Order safely.

    WHY THIS EXISTS:
    Pyright reported:
      Cannot access attribute "to_dict" for class "Order"
    because the model does not guarantee that helper method.

    This helper only uses `to_dict` if it actually exists at runtime.
    Otherwise it falls back to explicit field extraction.
    """
    td = getattr(order, "to_dict", None)
    if callable(td):
        try:
            out = td(include_items=False)
            if isinstance(out, dict):
                return out
        except TypeError:
            # Some older variants may not accept include_items
            try:
                out = td()
                if isinstance(out, dict):
                    return out
            except Exception:
                pass
        except Exception:
            pass

    return {
        "id": str(getattr(order, "order_id", getattr(order, "id", ""))),
        "order_id": str(getattr(order, "order_id", getattr(order, "id", ""))),
        "buyer_id": str(getattr(order, "buyer_id", "")) if getattr(order, "buyer_id", None) else None,
        "status": getattr(order, "status", None),
        "order_total": _safe_float(getattr(order, "order_total", getattr(order, "total", 0))),
        "delivery_method": getattr(order, "delivery_method", None),
        "delivery_address": getattr(order, "delivery_address", None),
        "delivery_status": getattr(order, "delivery_status", None),
        "expected_delivery_date": _iso(getattr(order, "expected_delivery_date", None)),
        "delivered_at": _iso(getattr(order, "delivered_at", None)),
        "order_date": _iso(getattr(order, "order_date", getattr(order, "created_at", None))),
        "created_at": _iso(getattr(order, "created_at", None)),
    }


# ----------------------------------------------------------------------------
# Route
# ----------------------------------------------------------------------------
@admin_bp.get("/overview")
@require_access_token
def overview() -> Response:
    """
    Admin dashboard overview data (fallback endpoint).
    """
    guard = _require_admin()
    if not isinstance(guard, User):
        return guard

    order_pk_col = _order_pk_col()
    order_date_col = _order_date_col()

    users_total = db.session.scalar(select(func.count()).select_from(User)) or 0
    products_total = db.session.scalar(select(func.count()).select_from(Product)) or 0
    orders_total = db.session.scalar(select(func.count()).select_from(Order)) or 0

    products_available = (
        db.session.scalar(
            select(func.count()).select_from(Product).where(
                (Product.status == "available") & (Product.quantity > 0)
            )
        )
        or 0
    )

    order_status_col = getattr(Order, "status", None)
    if order_status_col is not None:
        orders_pending = (
            db.session.scalar(
                select(func.count()).select_from(Order).where(order_status_col == "pending")
            )
            or 0
        )
    else:
        orders_pending = 0

    try:
        _last_seen, online_ids = presence_snapshot()
        users_online = len(online_ids)
    except Exception:
        users_online = 0

    recent_users: List[User] = db.session.scalars(
        select(User).order_by(User.created_at.desc()).limit(8)
    ).all()

    recent_products: List[Product] = db.session.scalars(
        select(Product)
        .options(selectinload(Product.farmer))
        .order_by(Product.created_at.desc())
        .limit(8)
    ).all()

    recent_orders_stmt = select(Order).options(
        selectinload(Order.buyer),
        selectinload(Order.items).selectinload(OrderItem.product),
    )

    if order_date_col is not None:
        recent_orders_stmt = recent_orders_stmt.order_by(order_date_col.desc())

    recent_orders: List[Order] = db.session.scalars(
        recent_orders_stmt.limit(8)
    ).all()

    users_out: List[Dict[str, Any]] = []
    for user_row in recent_users:
        user_payload = _user_out(user_row)
        try:
            user_payload["online"] = bool(presence_is_online(str(getattr(user_row, "id", ""))))
        except Exception:
            user_payload["online"] = False
        users_out.append(user_payload)

    orders_out: List[Dict[str, Any]] = []
    for order_row in recent_orders:
        order_payload = _order_out(order_row)
        order_payload["customer_name"] = getattr(getattr(order_row, "buyer", None), "full_name", None)
        order_payload["product_summary"] = _order_product_summary(order_row)
        orders_out.append(order_payload)

    products_out = [_product_out(product_row) for product_row in recent_products]

    return jsonify(
        {
            "success": True,
            "kpis": {
                "users_total": int(users_total),
                "products_total": int(products_total),
                "orders_total": int(orders_total),
                "products_available": int(products_available),
                "orders_pending": int(orders_pending),
                "users_online": int(users_online),
            },
            "recent": {
                "users": users_out,
                "products": products_out,
                "orders": orders_out,
            },
        }
    )