# ====================================================================
# backend/routes/admin_orders.py — Admin Order Management (JWT)
# ====================================================================
# FILE ROLE:
#   Admin-only endpoints to view/update orders:
#     • GET   /api/admin/orders
#     • PATCH /api/admin/orders/<id>   (status/payment updates)
# ====================================================================

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response

from sqlalchemy import select

from backend.database.db import db
from backend.models.user import ROLE_ADMIN, User
from backend.models.order import Order
from backend.utils.require_auth import require_access_token

admin_orders_bp = Blueprint("admin_orders", __name__)


def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _admin_guard() -> Optional[Response]:
    u = getattr(g, "current_user", None)
    if not isinstance(u, User):
        return _json({"success": False, "message": "Authentication required"}, 401)
    if u.role != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)
    return None


@admin_orders_bp.route("", methods=["GET"])
@require_access_token
def list_orders() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    status = (request.args.get("status") or "").strip().lower()

    stmt = select(Order)
    if status:
        stmt = stmt.where(Order.status == status)

    rows = db.session.execute(stmt.order_by(Order.order_date.desc()).limit(300)).scalars().all()
    return _json({"success": True, "orders": [o.to_dict() for o in rows]}, 200)


@admin_orders_bp.route("/<uuid:order_id>", methods=["PATCH"])
@require_access_token
def update_order(order_id) -> Response:  # type: ignore[no-untyped-def]
    guard = _admin_guard()
    if guard is not None:
        return guard

    payload = request.get_json(silent=True) or {}
    o = db.session.execute(select(Order).where(Order.id == order_id)).scalar_one_or_none()
    if o is None:
        return _json({"success": False, "message": "Order not found"}, 404)

    if "status" in payload:
        v = str(payload.get("status") or "").strip().lower()
        if v:
            o.status = v

    if "payment_status" in payload:
        v = str(payload.get("payment_status") or "").strip().lower()
        if v:
            o.payment_status = v

    if payload.get("mark_paid") is True:
        o.payment_status = "paid"
        o.paid_at = datetime.utcnow()

    db.session.commit()
    return _json({"success": True, "order": o.to_dict()}, 200)
