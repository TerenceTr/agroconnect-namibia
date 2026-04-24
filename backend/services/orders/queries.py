# ============================================================================
# backend/services/orders/queries.py — Orders query builders + filters
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Encapsulate:
#   • Visibility rules (admin/customer/farmer)
#   • Common querystring filters
#   • Eager loading strategy
# ============================================================================

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Tuple

from sqlalchemy import String, or_
from sqlalchemy.orm import selectinload

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User

from backend.services.orders.helpers import (
    flask,
    _role_is,
    _int_qp,
    _bool_qp,
    _order_pk_col,
    _order_date_col,
    _order_items_rel_attr,
    _product_pk_col,
    _product_owner_cols,
)


def order_query_for_user(user: User):
    q = db.session.query(Order)  # type: ignore[attr-defined]
    order_pk = _order_pk_col()
    oi_order_fk = getattr(OrderItem, "order_id")
    prod_pk = _product_pk_col()
    oi_prod_fk = getattr(OrderItem, "product_id")

    if _role_is(user, ROLE_ADMIN):
        return q

    if _role_is(user, ROLE_CUSTOMER):
        return q.filter(getattr(Order, "buyer_id") == user.id)

    if _role_is(user, ROLE_FARMER):
        # Broad query: any order that includes at least one of the farmer's items.
        owner_cols = _product_owner_cols()
        owner_filter = or_(*[(c == user.id) for c in owner_cols]) if owner_cols else (getattr(Product, "user_id") == user.id)

        return (
            q.join(OrderItem, oi_order_fk == order_pk)
            .join(Product, prod_pk == oi_prod_fk)
            .filter(owner_filter)
            .distinct()
        )

    return q.filter(getattr(Order, "buyer_id") == user.id)


def order_query_for_farmer_id(farmer_id):
    q = db.session.query(Order)  # type: ignore[attr-defined]
    order_pk = _order_pk_col()
    oi_order_fk = getattr(OrderItem, "order_id")
    prod_pk = _product_pk_col()
    oi_prod_fk = getattr(OrderItem, "product_id")

    owner_cols = _product_owner_cols()
    owner_filter = or_(*[(c == farmer_id) for c in owner_cols]) if owner_cols else (getattr(Product, "user_id") == farmer_id)

    return (
        q.join(OrderItem, oi_order_fk == order_pk)
        .join(Product, prod_pk == oi_prod_fk)
        .filter(owner_filter)
        .distinct()
    )


def apply_common_filters(q) -> Tuple[Any, int]:
    req = flask.request

    status = (req.args.get("status") or "").strip()
    payment_status = (req.args.get("payment_status") or "").strip()
    delivery_status = (req.args.get("delivery_status") or "").strip()
    delivery_method = (req.args.get("delivery_method") or "").strip()
    search_q = (req.args.get("q") or "").strip()

    if status and hasattr(Order, "status"):
        q = q.filter(getattr(Order, "status") == status)

    if payment_status and hasattr(Order, "payment_status"):
        q = q.filter(getattr(Order, "payment_status") == payment_status)

    if delivery_status and hasattr(Order, "delivery_status"):
        q = q.filter(getattr(Order, "delivery_status") == delivery_status)

    if delivery_method and hasattr(Order, "delivery_method"):
        q = q.filter(getattr(Order, "delivery_method") == delivery_method)

    days = _int_qp(req.args.get("days"), 0)
    if days > 0:
        col = _order_date_col()
        try:
            q = q.filter(col >= (datetime.utcnow() - timedelta(days=days)))
        except Exception:
            pass

    # ✅ never pass literal False into or_()
    if search_q:
        like = f"%{search_q}%"
        try:
            clauses = [_order_pk_col().cast(String).ilike(like)]
            if hasattr(Order, "payment_reference"):
                clauses.append(getattr(Order, "payment_reference").cast(String).ilike(like))
            q = q.filter(or_(*clauses))
        except Exception:
            pass

    limit = _int_qp(req.args.get("limit"), 200)
    limit = max(1, min(limit, 500))

    return q, limit


def apply_eager_loading(q, include_items: bool):
    rel = _order_items_rel_attr()
    if rel is None:
        return q

    if include_items and hasattr(OrderItem, "product"):
        return q.options(selectinload(rel).selectinload(getattr(OrderItem, "product")))
    return q.options(selectinload(rel))
