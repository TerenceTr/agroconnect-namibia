# ============================================================================
# backend/services/orders/helpers.py — Orders shared helpers (safe + schema-robust)
# ----------------------------------------------------------------------------
# FILE ROLE (brief):
#   Shared utilities used by Orders/Farmers/Ratings routes to:
#   • build JSON responses + read request.current_user safely
#   • parse common primitives (uuid, decimal, date/datetime)
#   • detect SQLAlchemy mapped *columns* (avoid @property in SQL expressions)
#   • handle cross-schema variants (PK names, product ownership columns, rel names)
# ============================================================================

from __future__ import annotations

import uuid
from datetime import date, datetime, time
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any, List, Optional, Tuple, cast

import flask as _flask
from sqlalchemy import or_
from sqlalchemy.orm import selectinload

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User

# ----------------------------------------------------------------------------
# Pyright-friendly Flask access (prevents "Unknown member" noise)
# ----------------------------------------------------------------------------
flask: Any = cast(Any, _flask)
ResponseT = Any

# ----------------------------------------------------------------------------
# Response + auth helpers
# ----------------------------------------------------------------------------
def _json(payload: Any, status: int = 200) -> ResponseT:
    """Standard JSON response helper."""
    resp = flask.jsonify(payload)
    resp.status_code = status
    return resp


def _current_user() -> Optional[User]:
    """
    Access user attached by auth middleware (token_required / require_access_token).
    Keeps strict typing: return User or None.
    """
    u = getattr(flask.request, "current_user", None)
    return u if isinstance(u, User) else None


def _role_is(user: User, role_const: int) -> bool:
    """Role compare that survives bad data types."""
    try:
        return int(getattr(user, "role", 0)) == int(role_const)
    except Exception:
        return False


# ----------------------------------------------------------------------------
# Parsing helpers (never raise)
# ----------------------------------------------------------------------------
def _to_uuid(value: Any) -> Optional[uuid.UUID]:
    """Best-effort UUID parsing from anything."""
    try:
        s = str(value).strip()
        if not s:
            return None
        return uuid.UUID(s)
    except Exception:
        return None


def _to_decimal(value: Any) -> Decimal:
    """Best-effort Decimal parsing; invalid -> 0."""
    if value is None:
        return Decimal("0")
    if isinstance(value, Decimal):
        return value
    raw = str(value).strip()
    if not raw:
        return Decimal("0")
    try:
        return Decimal(raw)
    except (InvalidOperation, ValueError):
        return Decimal("0")


def _money(x: Any) -> Decimal:
    """Money quantization (2dp) with defensive fallback."""
    try:
        d = _to_decimal(x)
        return d.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except Exception:
        return Decimal("0.00")


def _bool_qp(value: Any) -> bool:
    """Query-param boolean parser."""
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _int_qp(value: Any, default: int) -> int:
    """Query-param int parser."""
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _parse_iso(value: Any) -> Optional[datetime]:
    """
    Parse ISO-ish datetime safely.
    Accepts trailing "Z" by stripping it (DB often stores naive timestamps).
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    s = str(value).strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1]
    try:
        return datetime.fromisoformat(s)
    except Exception:
        return None


def _parse_date(value: Any) -> Optional[date]:
    """Parse date or datetime into date safely."""
    if value is None:
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()

    s = str(value).strip()
    if not s:
        return None

    # date-only (YYYY-MM-DD)
    try:
        if len(s) >= 10 and s[4] == "-" and s[7] == "-":
            return date.fromisoformat(s[:10])
    except Exception:
        pass

    # datetime-ish
    try:
        dt = datetime.fromisoformat(s[:-1] if s.endswith("Z") else s)
        return dt.date()
    except Exception:
        return None


def _date_to_datetime(d: Optional[date]) -> Optional[datetime]:
    """DBs often store expected_delivery_date in a datetime column."""
    if d is None:
        return None
    try:
        return datetime.combine(d, time.min)
    except Exception:
        return None


def _dt_iso(dt: Any) -> Optional[str]:
    """✅ Safe datetime -> ISO string (never call isoformat() on None)."""
    return dt.isoformat() if isinstance(dt, datetime) else None


def _maybe_set(obj: Any, attr: str, value: Any) -> None:
    """Set attribute only if it exists (schema-robust)."""
    try:
        if hasattr(obj, attr):
            setattr(obj, attr, value)
    except Exception:
        return


def _maybe_get(obj: Any, attr: str, default: Any = None) -> Any:
    """Get attribute only if it exists (schema-robust)."""
    try:
        return getattr(obj, attr, default) if hasattr(obj, attr) else default
    except Exception:
        return default


# ----------------------------------------------------------------------------
# SQLAlchemy introspection helpers
# ----------------------------------------------------------------------------
def _is_mapped_column_attr(attr: Any) -> bool:
    """
    True if `attr` looks like a SQLAlchemy mapped *column* attribute.
    (Not @property, not relationship.)
    """
    try:
        prop = getattr(attr, "property", None)
        cols = getattr(prop, "columns", None)
        return bool(cols)
    except Exception:
        return False


def _first_mapped_attr(model: Any, names: Tuple[str, ...]) -> Optional[Any]:
    """Return first name that exists on model and is a mapped column."""
    for n in names:
        if hasattr(model, n):
            a = getattr(model, n)
            if _is_mapped_column_attr(a):
                return a
    return None


# ----------------------------------------------------------------------------
# Cross-schema model helpers (PKs, FK columns, relationship names)
# ----------------------------------------------------------------------------
def _order_pk_col() -> Any:
    """
    Return a *mapped* PK column attribute for Order.
    Prefer mapped columns only to avoid @property in SQL expressions.
    """
    a = _first_mapped_attr(Order, ("id", "order_id"))
    return a if a is not None else getattr(Order, "id", getattr(Order, "order_id"))


def _order_pk_value(order: Order) -> Optional[uuid.UUID]:
    """Return UUID pk from an Order instance for either (id | order_id)."""
    for attr in ("id", "order_id"):
        try:
            if hasattr(order, attr):
                v = getattr(order, attr)
                if isinstance(v, uuid.UUID):
                    return v
                u = _to_uuid(v)
                if u:
                    return u
        except Exception:
            continue
    return None


def _ensure_order_pk(order: Order) -> None:
    """
    Ensure Order has a UUID PK before flush/return payload.
    Always set mapped attribute (usually `id`).
    """
    # Most common: Order.id is mapped UUID
    if hasattr(order, "id"):
        try:
            if getattr(order, "id", None) is None:
                setattr(order, "id", uuid.uuid4())
                return
        except Exception:
            pass

    # Fallback if schema maps order_id directly
    if hasattr(order, "order_id") and _is_mapped_column_attr(getattr(Order, "order_id")):
        try:
            if getattr(order, "order_id", None) is None:
                setattr(order, "order_id", uuid.uuid4())
        except Exception:
            pass


def _order_items_rel_attr() -> Optional[Any]:
    """Return the Order -> items relationship attribute name across schemas."""
    if hasattr(Order, "items"):
        return getattr(Order, "items")
    if hasattr(Order, "order_items"):
        return getattr(Order, "order_items")
    return None


def _order_items_loader() -> Optional[Any]:
    """selectinload option for Order items relationship (if available)."""
    rel = _order_items_rel_attr()
    if rel is None:
        return None
    try:
        return selectinload(rel)
    except Exception:
        return None


def _order_date_col() -> Any:
    """Order date column across schemas (order_date | created_at)."""
    a = _first_mapped_attr(Order, ("order_date", "created_at", "createdAt"))
    return a if a is not None else _order_pk_col()


def _product_pk_col() -> Any:
    """Product primary key across schemas (product_id | id)."""
    a = _first_mapped_attr(Product, ("product_id", "id"))
    return a if a is not None else getattr(Product, "product_id", getattr(Product, "id"))


def _product_pk_value(p: Product) -> Optional[uuid.UUID]:
    v = getattr(p, "product_id", None) or getattr(p, "id", None)
    if isinstance(v, uuid.UUID):
        return v
    return _to_uuid(v)


def _product_qty_col() -> Optional[Any]:
    """Quantity/stock column across schemas."""
    return _first_mapped_attr(Product, ("quantity", "stock", "qty", "units"))


def _product_status_col() -> Optional[Any]:
    """Status column across schemas (optional)."""
    return _first_mapped_attr(Product, ("status", "product_status", "state"))


def _product_name_col() -> Optional[Any]:
    """Product name column across schemas."""
    return _first_mapped_attr(Product, ("product_name", "name", "title"))


def _product_owner_cols() -> List[Any]:
    """
    Candidate mapped columns representing product ownership across schema variants.
    Common in your DB: products.user_id.
    """
    candidates: List[Any] = []
    for name in ("user_id", "farmer_id", "owner_id", "created_by_id", "seller_id"):
        if hasattr(Product, name):
            attr = getattr(Product, name)
            if _is_mapped_column_attr(attr):
                candidates.append(attr)

    # If not mapped (rare), still keep a raw attribute if present to allow getattr usage
    if not candidates and hasattr(Product, "user_id"):
        candidates.append(getattr(Product, "user_id"))

    # De-dupe
    seen: set[int] = set()
    out: List[Any] = []
    for c in candidates:
        cid = id(c)
        if cid not in seen:
            seen.add(cid)
            out.append(c)
    return out


def _product_owner_id(p: Product) -> Optional[uuid.UUID]:
    """Best-effort owner id (columns first, then relationship objects)."""
    for name in ("user_id", "farmer_id", "owner_id", "created_by_id", "seller_id"):
        try:
            v = getattr(p, name, None)
            if isinstance(v, uuid.UUID):
                return v
            u = _to_uuid(v)
            if u:
                return u
        except Exception:
            continue

    for rel_name in ("user", "farmer", "owner", "created_by", "seller"):
        try:
            rel = getattr(p, rel_name, None)
            if rel is None:
                continue
            rid = getattr(rel, "id", None)
            if isinstance(rid, uuid.UUID):
                return rid
            u = _to_uuid(rid)
            if u:
                return u
        except Exception:
            continue

    return None


def _product_owned_by(p: Product, owner_id: uuid.UUID) -> bool:
    """Owner compare that survives UUID vs string types."""
    oid = _product_owner_id(p)
    return bool(oid and str(oid) == str(owner_id))


def _get_order_items(order: Order) -> List[Any]:
    """Return items array regardless of relationship name."""
    items = getattr(order, "items", None)
    if isinstance(items, list):
        return items
    items2 = getattr(order, "order_items", None)
    if isinstance(items2, list):
        return items2
    try:
        if items is not None:
            return list(items)
        if items2 is not None:
            return list(items2)
    except Exception:
        pass
    return []


def _order_item_order_fk_col() -> Optional[Any]:
    """OrderItem -> Order FK column across schemas."""
    return _first_mapped_attr(OrderItem, ("order_id", "orderId"))


def _order_item_product_fk_col() -> Optional[Any]:
    """OrderItem -> Product FK column across schemas."""
    return _first_mapped_attr(OrderItem, ("product_id", "productId"))


def _get_item_product_or_fetch(item: Any) -> Optional[Product]:
    """
    Get Product from OrderItem relationship if present,
    else fetch by OrderItem.product_id using product pk column.
    """
    p = getattr(item, "product", None)
    if isinstance(p, Product):
        return p

    pid_raw = getattr(item, "product_id", None) or getattr(item, "productId", None)
    pid = _to_uuid(pid_raw)
    if pid is None:
        return None

    try:
        # Query by mapped pk col (schema-robust)
        return (
            db.session.query(Product)  # type: ignore[attr-defined]
            .filter(_product_pk_col() == pid)
            .first()
        )
    except Exception:
        return None


def _order_is_exclusively_farmer(order: Order, farmer_id: uuid.UUID) -> bool:
    """
    True if all items in order belong to the given farmer.
    Useful when a customer checkout is split OR when a farmer must not
    see/update mixed orders (prevents Forbidden errors).
    """
    items = _get_order_items(order)
    if not items:
        return False

    for it in items:
        p = _get_item_product_or_fetch(it)
        if p is None or not _product_owned_by(p, farmer_id):
            return False

    return True
