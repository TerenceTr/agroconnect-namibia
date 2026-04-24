# ============================================================================
# backend/services/orders/serialization.py — Order JSON serialization (UI-safe)
# ----------------------------------------------------------------------------
# FILE ROLE (brief):
#   Converts Order ORM objects into JSON payloads for the API.
#   • Works with eager-loaded ORM objects (Order + items + product relationship)
#   • Supports farmer-scoped serialization (filtering items to a farmer)
#   • Outputs a stable, UI-friendly shape even when DB schemas vary
#
# STABILITY / COMPATIBILITY (THIS VERSION):
#   ✅ Keeps Protocols minimal so real SQLAlchemy ORM models match
#   ✅ Uses getattr() everywhere for optional fields (schema drift safe)
#   ✅ Never calls isoformat() on None (safe datetime/date serialization)
#   ✅ Provides BOTH:
#       - items_preview (string, UI-friendly)
#       - items_preview_list (first 3 item dicts)
#   ✅ Adds best-effort per-item partial-delivery fields when present
#      (e.g., delivered_quantity / delivery_status on OrderItem)
# ============================================================================

from __future__ import annotations

import uuid
from decimal import Decimal
from typing import Any, Dict, List, Optional, Protocol, Sequence, Tuple, TYPE_CHECKING, cast

from backend.services.orders.helpers import (
    _to_uuid,
    _to_decimal,
    _money,
    _maybe_get,
    _get_order_items,
    _get_item_product_or_fetch,
    _product_owned_by,
    _order_pk_value,
)

if TYPE_CHECKING:
    from backend.models.order import Order  # noqa: F401


class _UserLike(Protocol):
    id: Any
    name: Any
    full_name: Any
    username: Any
    email: Any
    phone: Any
    first_name: Any
    last_name: Any


class _OrderLike(Protocol):
    buyer_id: Any
    buyer: Any
    status: Any
    order_total: Any
    total: Any
    order_date: Any
    created_at: Any


def _safe_dt(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        return v.isoformat()
    except Exception:
        return None


def _str_uuid(v: Any) -> Optional[str]:
    if v is None:
        return None
    try:
        if isinstance(v, uuid.UUID):
            return str(v)
        u = _to_uuid(v)
        return str(u) if u else str(v)
    except Exception:
        return None


def _safe_decimal(v: Any, default: Decimal = Decimal("0")) -> Decimal:
    d = _to_decimal(v)
    return d if isinstance(d, Decimal) else default


def _pick_name(user: Any) -> str:
    if user is None:
        return "Customer"
    try:
        full = getattr(user, "name", None) or getattr(user, "full_name", None)
        if full:
            return str(full)
        first = getattr(user, "first_name", None)
        last = getattr(user, "last_name", None)
        if first or last:
            return str(f"{first or ''} {last or ''}").strip() or "Customer"
        return str(getattr(user, "username", None) or "Customer")
    except Exception:
        return "Customer"


def _make_items_preview(items: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]], int]:
    count = len(items)
    names: List[str] = []
    for it in items:
        n = it.get("product_name") or it.get("name")
        if n:
            names.append(str(n))

    head = names[:3]
    preview = ", ".join(head) if head else ""
    if count > 3:
        preview = f"{preview} +{count - 3} more" if preview else f"+{count - 3} more"

    return preview, items[:3], count


def build_buyer_map(orders: Sequence[_OrderLike]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}

    for o in orders:
        bid = _str_uuid(getattr(o, "buyer_id", None))
        if not bid or bid in out:
            continue

        buyer = getattr(o, "buyer", None)
        if buyer is None:
            out[bid] = {"id": bid, "name": "Customer"}
            continue

        out[bid] = {
            "id": bid,
            "name": _pick_name(buyer),
            "email": getattr(buyer, "email", None),
            "phone": getattr(buyer, "phone", None),
        }

    return out


def serialize_order(
    order: _OrderLike,
    *,
    include_items: bool,
    buyer_map: Dict[str, Dict[str, Any]],
    farmer_id: Optional[uuid.UUID] = None,
) -> Dict[str, Any]:
    order_any = cast(Any, order)

    oid = _order_pk_value(order_any)
    buyer_id = _str_uuid(getattr(order, "buyer_id", None))

    total_raw = getattr(order, "order_total", None) or getattr(order, "total", None) or 0
    total = _money(_safe_decimal(total_raw, Decimal("0.00")))

    item_dicts: List[Dict[str, Any]] = []

    if include_items:
        for it in _get_order_items(order_any):
            p = _get_item_product_or_fetch(it)

            qty = _safe_decimal(getattr(it, "quantity", None) or getattr(it, "qty", None) or 0, Decimal("0"))

            unit_price = _money(
                _safe_decimal(
                    getattr(it, "unit_price", None)
                    or getattr(it, "unitPrice", None)
                    or getattr(p, "price", None)
                    or 0,
                    Decimal("0.00"),
                )
            )

            line_total_raw = getattr(it, "line_total", None) or getattr(it, "lineTotal", None)
            line_total = (
                _money(_safe_decimal(line_total_raw, Decimal("0.00")))
                if line_total_raw is not None
                else _money(unit_price * qty)
            )

            owned_by_farmer = False
            if farmer_id:
                try:
                    if p is not None:
                        owned_by_farmer = _product_owned_by(p, farmer_id)
                except Exception:
                    owned_by_farmer = False

            product_id = (
                _str_uuid(getattr(p, "product_id", None) or getattr(p, "id", None))
                or _str_uuid(getattr(it, "product_id", None))
                or _str_uuid(getattr(it, "productId", None))
            )

            product_name = (
                (getattr(p, "product_name", None) or getattr(p, "name", None))
                if p is not None
                else None
            )
            product_name = product_name or getattr(it, "product_name", None) or getattr(it, "name", None) or "Product"

            delivered_qty = (
                getattr(it, "delivered_quantity", None)
                or getattr(it, "delivered_qty", None)
                or getattr(it, "qty_delivered", None)
                or getattr(it, "fulfilled_quantity", None)
            )
            delivered_qty_dec = _to_decimal(delivered_qty)
            delivered_qty_str = str(delivered_qty_dec) if isinstance(delivered_qty_dec, Decimal) else None

            item_delivery_status = (
                getattr(it, "delivery_status", None)
                or getattr(it, "item_delivery_status", None)
                or getattr(it, "fulfillment_status", None)
            )

            item_delivered_at = _safe_dt(
                getattr(it, "delivered_at", None)
                or getattr(it, "item_delivered_at", None)
                or getattr(it, "fulfilled_at", None)
            )

            item_dicts.append(
                {
                    "order_item_id": _str_uuid(getattr(it, "id", None) or getattr(it, "order_item_id", None)),
                    "product_id": product_id,
                    "product_name": str(product_name),
                    "quantity": str(qty),
                    "unit_price": str(_money(unit_price)),
                    "line_total": str(_money(line_total)),
                    "unit": getattr(it, "unit", None),
                    "pack_size": getattr(it, "pack_size", None),
                    "pack_unit": getattr(it, "pack_unit", None),
                    "delivered_quantity": delivered_qty_str,
                    "item_delivery_status": item_delivery_status,
                    "item_delivered_at": item_delivered_at,
                    "_owned_by_farmer": owned_by_farmer,
                }
            )

    if farmer_id and include_items:
        header_farmer = _to_uuid(_maybe_get(order, "farmer_id"))
        if not (header_farmer and str(header_farmer) == str(farmer_id)):
            item_dicts = [d for d in item_dicts if d.get("_owned_by_farmer") is True]

        scoped_total = Decimal("0.00")
        for d in item_dicts:
            scoped_total += _safe_decimal(d.get("line_total"), Decimal("0.00"))
        total = _money(scoped_total)

    for d in item_dicts:
        d.pop("_owned_by_farmer", None)

    items_preview_text, items_preview_list, item_count = _make_items_preview(item_dicts)

    order_dt = getattr(order, "order_date", None) or getattr(order, "created_at", None)
    buyer_info = buyer_map.get(buyer_id or "", {"id": buyer_id, "name": "Customer"})

    return {
        "order_id": _str_uuid(oid),
        "id": _str_uuid(oid),
        "buyer_id": buyer_id,
        "buyer": buyer_info,
        "buyer_name": buyer_info.get("name"),
        "status": getattr(order, "status", None),
        "payment_status": getattr(order, "payment_status", None),
        "payment_method": getattr(order, "payment_method", None),
        "payment_reference": getattr(order, "payment_reference", None),
        "paid_at": _safe_dt(getattr(order, "paid_at", None)),
        "order_total": str(_money(total)),
        "total": str(_money(total)),
        "total_amount": str(_money(total)),
        "order_date": _safe_dt(order_dt),
        "created_at": _safe_dt(getattr(order, "created_at", None)),
        "delivery_method": getattr(order, "delivery_method", None),
        "delivery_address": getattr(order, "delivery_address", None),
        "delivery_status": getattr(order, "delivery_status", None),
        "expected_delivery_date": _safe_dt(getattr(order, "expected_delivery_date", None)),
        "delivered_at": _safe_dt(getattr(order, "delivered_at", None)),
        "items": item_dicts if include_items else None,
        "items_preview": items_preview_text,
        "items_preview_list": items_preview_list,
        "item_count": item_count,
    }
