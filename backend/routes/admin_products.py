# ====================================================================
# backend/routes/admin_products.py — Admin Moderation (JWT)
# --------------------------------------------------------------------
# FILE ROLE:
#   Product listing moderation for AdminModerationPage.
#
# ROUTES:
#   GET  /api/admin/products/pending
#   POST /api/admin/products/<id>/approve
#   POST /api/admin/products/<id>/reject
#
# FIX INCLUDED:
#   Pylance/Pyright error:
#     "Argument of type 'bool' cannot be assigned to parameter 'whereclause'..."
#   occurs when Product.status (or Product.id) is incorrectly implemented as a
#   plain Python attribute or @property instead of a mapped column.
#
#   With the updated Product model (Mapped[...] columns), comparisons like:
#       Product.status == "pending"
#   produce SQL expressions (not booleans), and the warning disappears.
# ====================================================================

from __future__ import annotations

import uuid
from typing import Any, Optional, cast

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response

from sqlalchemy import select

from backend.database.db import db
from backend.models.user import ROLE_ADMIN, User
from backend.models.product import Product
from backend.utils.require_auth import require_access_token

admin_products_bp = Blueprint("admin_products", __name__)


def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return cast(Response, resp)


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
    if u is None:
        return _json({"success": False, "message": "Authentication required"}, 401)
    if int(getattr(u, "role", 0) or 0) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)
    return None


def _safe_uuid(s: str) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(s))
    except Exception:
        return None


@admin_products_bp.route("/products/pending", methods=["GET"])
@require_access_token
def pending_products() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    rows = db.session.execute(
        select(Product, User.full_name.label("farmer_name"))
        .join(User, User.id == Product.farmer_id, isouter=True)
        .where(Product.status == "pending")
        .order_by(Product.created_at.desc())
    ).all()

    payload: list[dict[str, Any]] = []
    for p, farmer_name in rows:
        payload.append(
            {
                "id": str(p.id),
                "name": p.name,
                "status": p.status,
                "created_at": p.created_at.isoformat() if p.created_at else None,
                "farmer_name": farmer_name,
            }
        )

    return _json(payload, 200)


def _act(product_id: str, new_status: str) -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    pid = _safe_uuid(product_id)
    if pid is None:
        return _json({"success": False, "message": "Invalid product id"}, 400)

    p = db.session.execute(select(Product).where(Product.id == pid)).scalar_one_or_none()
    if p is None:
        return _json({"success": False, "message": "Product not found"}, 404)

    p.status = new_status
    db.session.commit()

    return _json({"success": True, "id": str(p.id), "status": p.status}, 200)


@admin_products_bp.route("/products/<product_id>/approve", methods=["POST"])
@require_access_token
def approve(product_id: str) -> Response:
    return _act(product_id, "available")


@admin_products_bp.route("/products/<product_id>/reject", methods=["POST"])
@require_access_token
def reject(product_id: str) -> Response:
    return _act(product_id, "rejected")
