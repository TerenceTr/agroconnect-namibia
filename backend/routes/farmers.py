# ============================================================================
# backend/routes/farmers.py — Farmer APIs (Profile + Overview Dashboard)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Farmer dashboard backend:
#   • Paid-only KPIs (revenue/items sold) via payments.status='paid'
#   • Revenue trend (gap-filled) with bucket=day|week|month|bimonth|quarter|year
#   • Recent orders (buyer + address + payment + partial delivery progress) — PAID ONLY
#   • Top products by revenue + by quantity (paid-only)
#   • Farmer ranking (orders received + ratings) [best-effort, DB-safe]
#
# KEY UPDATE (your locked requirements):
#   ✅ Adds OPTIONAL calendar window params for Trend + Recent Orders ONLY:
#        - trend_start_date=YYYY-MM-DD
#        - trend_end_date=YYYY-MM-DD
#      (also accepts legacy synonyms: start_date/end_date/window_start_date/window_end_date)
#
#   ✅ Paid-only enforcement:
#        - Revenue trend already paid-only ✅
#        - Recent orders now PAID ONLY ✅ (payments.status='paid')
#
#   ✅ Bucket support extended:
#        - week, bimonth (Jan–Feb, Mar–Apr...), quarter, year (annual)
#
#   ✅ Date display fields returned in DD-MM-YYYY for UI:
#        - revenue_trend[].date_display
#        - recent_orders[].order_date_display
#        - (ISO fields kept for transport)
#
# FIXES IN THIS VERSION:
#   ✅ "send_file is unknown import symbol" (Pyright/Pylance):
#      - Avoid direct symbol import paths that some stubs miss.
#      - Import flask module and access send_file via cast(Any, flask).send_file
#   ✅ "Argument of type 'str | None' cannot be assigned to parameter 'raw' of type 'str' in _parse_bucket":
#      - request.args.get(...) returns Optional[str]
#      - _parse_bucket now accepts Optional[str] (and safely normalizes)
#   ✅ "Code is too complex to analyze":
#      - Kept logic in small subroutines (trend, recent orders, exports, etc.)
# ============================================================================

from __future__ import annotations

import csv
from datetime import date, datetime, time, timedelta
from functools import lru_cache
from io import BytesIO, StringIO
from typing import Any, Dict, List, Optional, Tuple, cast
from uuid import UUID

import flask as _flask
from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import MetaData, Table
from sqlalchemy import case, desc, exists, func, inspect, literal, select, text

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_FARMER, User
from backend.security import token_required

# ----------------------------------------------------------------------------
# NOTE: Avoid "from flask.helpers import send_file" (some type stubs complain).
#       Use module attribute via cast(Any, flask).send_file.
# ----------------------------------------------------------------------------
send_file = cast(Any, _flask).send_file

farmers_bp = Blueprint("farmers", __name__)

LOW_STOCK_THRESHOLD = 5


# ----------------------------- small helpers ------------------------------
def _utc_now() -> datetime:
    return datetime.utcnow()


def _safe_float(v: Any) -> float:
    try:
        return float(v)
    except Exception:
        return 0.0


def _safe_int(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        return 0


def _money2(v: Any) -> float:
    return round(_safe_float(v), 2)


def _dt_iso(v: Any) -> Optional[str]:
    return v.isoformat() if isinstance(v, datetime) else None


def _date_iso(v: Any) -> Optional[str]:
    if isinstance(v, datetime):
        return v.date().isoformat()
    return v.isoformat() if isinstance(v, date) else None


def _ddmmyyyy(v: Any) -> Optional[str]:
    """Display format: DD-MM-YYYY (ISO fields remain for machines)."""
    if isinstance(v, datetime):
        return v.strftime("%d-%m-%Y")
    if isinstance(v, date):
        return v.strftime("%d-%m-%Y")
    return None


def _json_error(msg: str, status: int):
    resp = jsonify({"success": False, "message": msg})
    resp.status_code = status
    return resp


def _current_user() -> Optional[User]:
    u = getattr(request, "current_user", None)
    return u if isinstance(u, User) else None


def _to_uuid(v: Any) -> Optional[UUID]:
    try:
        s = str(v or "").strip()
        return UUID(s) if s else None
    except Exception:
        return None


def _num_display(v: Any, decimals: int = 3) -> str:
    """
    UI-friendly numeric display:
      - 12.000 -> "12"
      - 12.500 -> "12.5"
      - 12.345 -> "12.345"
    """
    x = _safe_float(v)
    if abs(x - round(x)) < 1e-9:
        return str(int(round(x)))
    s = f"{x:.{decimals}f}".rstrip("0").rstrip(".")
    return s if s else "0"


def _pct_change(curr: float, prev: float) -> Optional[float]:
    prev_f = _safe_float(prev)
    curr_f = _safe_float(curr)
    if prev_f <= 0:
        return None
    return round(((curr_f - prev_f) / prev_f) * 100.0, 2)


def _parse_date_yyyy_mm_dd(raw: Any) -> Optional[date]:
    s = str(raw or "").strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def _shift_year_safe(d: date, years: int) -> date:
    """Shift by N years, clamping to last day of month if needed (e.g., Feb 29)."""
    y = d.year + years
    m = d.month
    day = d.day
    try:
        return date(y, m, day)
    except Exception:
        # clamp
        last = (date(y, m + 1, 1) - timedelta(days=1)) if m < 12 else date(y, 12, 31)
        return date(y, m, min(day, last.day))


def _window_dt(start_d: date, end_d: date) -> Tuple[datetime, datetime]:
    """
    Inclusive date range -> [start_dt, end_exclusive_dt)
    """
    start_dt = datetime.combine(start_d, time.min)
    end_excl = datetime.combine(end_d + timedelta(days=1), time.min)
    return start_dt, end_excl


# ----------------------------- schema helpers -----------------------------
def _has_table(name: str) -> bool:
    try:
        return bool(inspect(db.engine).has_table(name))
    except Exception:
        return False


def _order_dt_col() -> Any:
    # DB has order_date; some legacy code uses created_at
    return getattr(Order, "order_date", None) or getattr(Order, "created_at", None)


def _order_pk_col() -> Any:
    # Prefer real mapped PK attribute if available
    return getattr(Order, "id", None) or getattr(Order, "order_id", None)


def _order_pk_attr_name() -> str:
    if hasattr(Order, "id"):
        return "id"
    if hasattr(Order, "order_id"):
        return "order_id"
    return "id"


def _order_buyer_id_col() -> Optional[Any]:
    return getattr(Order, "buyer_id", None)


def _product_pk_col() -> Any:
    return getattr(Product, "product_id", None) or getattr(Product, "id", None)


def _product_owner_col() -> Any:
    for name in ("user_id", "farmer_id", "owner_id", "created_by_id", "seller_id"):
        if hasattr(Product, name):
            return getattr(Product, name)
    return getattr(Product, "user_id")


def _product_name_col() -> Any:
    return getattr(Product, "product_name", None) or getattr(Product, "name")


def _product_qty_col() -> Optional[Any]:
    return getattr(Product, "quantity", None) or getattr(Product, "stock", None)


def _oi_order_id_col() -> Any:
    return getattr(OrderItem, "order_id", None) or getattr(OrderItem, "orderId")


def _oi_product_id_col() -> Any:
    return getattr(OrderItem, "product_id", None) or getattr(OrderItem, "productId")


def _revenue_expr() -> Any:
    line_total = getattr(OrderItem, "line_total", None)
    if line_total is not None:
        return func.coalesce(line_total, OrderItem.unit_price * OrderItem.quantity)
    return OrderItem.unit_price * OrderItem.quantity


def _user_name_expr() -> Any:
    for name in ("full_name", "name", "username", "email"):
        col = getattr(User, name, None)
        if col is not None:
            return col
    return literal(None)


def _user_phone_expr() -> Any:
    for name in ("phone", "phone_number", "mobile"):
        col = getattr(User, name, None)
        if col is not None:
            return col
    return literal(None)


def _user_location_expr() -> Any:
    for name in ("location", "address", "region", "city", "town", "constituency"):
        col = getattr(User, name, None)
        if col is not None:
            return col
    return literal(None)


# ----------------------------- payments helpers ---------------------------
@lru_cache(maxsize=1)
def _payments_table() -> Optional[Table]:
    if not _has_table("payments"):
        return None
    try:
        return Table("payments", MetaData(), autoload_with=db.engine)
    except Exception:
        return None


def _paid_predicate(order_pk_expr: Any) -> Any:
    """Paid detection via payments.status='paid' using EXISTS (alias-safe)."""
    p = _payments_table()
    if p is None:
        return text("1=0")

    status_col = getattr(p.c, "status", None)
    order_id_col = getattr(p.c, "order_id", None)
    if status_col is None or order_id_col is None:
        return text("1=0")

    return exists(
        select(1)
        .select_from(p)
        .where(order_id_col == order_pk_expr)
        .where(func.lower(func.coalesce(status_col, "")) == "paid")
    )


def _payments_map_for_orders(order_ids: List[UUID]) -> Dict[str, Dict[str, Any]]:
    """
    Latest payment row per order (best-effort; DB-agnostic, avoids raw SQL).
    Returns: { "<order_id>": {payment_status, payment_method, payment_reference, paid_at, paid_at_display} }
    """
    if not order_ids:
        return {}

    p = _payments_table()
    if p is None:
        return {}

    order_id_col = getattr(p.c, "order_id", None)
    status_col = getattr(p.c, "status", None)
    method_col = getattr(p.c, "method", None)
    ref_col = getattr(p.c, "reference", None)
    updated_col = getattr(p.c, "updated_at", None)

    if order_id_col is None or status_col is None:
        return {}

    try:
        stmt = (
            select(
                order_id_col,
                status_col,
                method_col if method_col is not None else literal(None),
                ref_col if ref_col is not None else literal(None),
                updated_col if updated_col is not None else literal(None),
            )
            .where(order_id_col.in_(order_ids))
            .order_by(order_id_col, desc(updated_col) if updated_col is not None else desc(status_col))
        )
        rows = db.session.execute(stmt).fetchall()

        out: Dict[str, Dict[str, Any]] = {}
        seen: set[str] = set()
        for oid, status, method, reference, updated_at in rows:
            k = str(oid)
            if k in seen:
                continue
            seen.add(k)
            out[k] = {
                "payment_status": str(status or "unpaid").lower(),
                "payment_method": method,
                "payment_reference": reference,
                "paid_at": _dt_iso(updated_at),
                "paid_at_display": _ddmmyyyy(updated_at),
            }
        return out
    except Exception:
        return {}


# ----------------------------- bucketing helpers ---------------------------
def _week_start(d: date) -> date:
    return d - timedelta(days=d.weekday())


def _month_start(d: date) -> date:
    return date(d.year, d.month, 1)


def _bimonth_start(d: date) -> date:
    """
    Bi-month periods are:
      Jan–Feb, Mar–Apr, May–Jun, Jul–Aug, Sep–Oct, Nov–Dec
    Start month is the odd month (1,3,5,7,9,11).
    """
    m = d.month
    start_m = m if (m % 2 == 1) else (m - 1)
    if start_m < 1:
        start_m = 1
    return date(d.year, start_m, 1)


def _quarter_start(d: date) -> date:
    qm = ((d.month - 1) // 3) * 3 + 1  # Q1=Jan, Q2=Apr, Q3=Jul, Q4=Oct
    return date(d.year, qm, 1)


def _year_start(d: date) -> date:
    return date(d.year, 1, 1)


def _add_months(d: date, months: int) -> date:
    y = d.year + ((d.month - 1 + months) // 12)
    m = ((d.month - 1 + months) % 12) + 1
    return date(y, m, 1)


def _add_quarters(d: date, quarters: int) -> date:
    return _add_months(d, 3 * quarters)


def _add_years(d: date, years: int) -> date:
    return date(d.year + years, 1, 1)


def _bucket_key(bucket: str, d: date) -> date:
    if bucket == "day":
        return d
    if bucket == "week":
        return _week_start(d)
    if bucket == "month":
        return _month_start(d)
    if bucket == "bimonth":
        return _bimonth_start(d)
    if bucket == "quarter":
        return _quarter_start(d)
    return _year_start(d)


def _bucket_start_for_window(bucket: str, window_start: date) -> date:
    return _bucket_key(bucket, window_start)


def _stepper(bucket: str):
    if bucket == "day":
        return lambda d: d + timedelta(days=1)
    if bucket == "week":
        return lambda d: d + timedelta(days=7)
    if bucket == "month":
        return lambda d: _add_months(d, 1)
    if bucket == "bimonth":
        return lambda d: _add_months(d, 2)
    if bucket == "quarter":
        return lambda d: _add_quarters(d, 1)
    return lambda d: _add_years(d, 1)


# ----------------------------- query helpers ------------------------------
def _daily_revenue_series(
    farmer_id: UUID,
    dt_min: datetime,
    dt_max_excl: Optional[datetime] = None,
) -> Dict[date, float]:
    """
    DB-agnostic daily revenue series for PAID orders only.
    Range is [dt_min, dt_max_excl) if dt_max_excl is provided.
    Returns: { date: revenue }
    """
    order_dt = _order_dt_col()
    if order_dt is None:
        return {}

    order_pk = _order_pk_col()
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()

    revenue_expr = _revenue_expr()
    paid_pred = _paid_predicate(order_pk)

    q = (
        db.session.query(
            func.date(order_dt).label("k"),
            func.coalesce(func.sum(revenue_expr), 0).label("v"),
        )
        .select_from(OrderItem)
        .join(Product, oi_product_id == product_pk)
        .join(Order, oi_order_id == order_pk)
        .filter(owner_col == farmer_id)
        .filter(order_dt >= dt_min)
        .filter(paid_pred)
    )
    if dt_max_excl is not None:
        q = q.filter(order_dt < dt_max_excl)

    out: Dict[date, float] = {}
    try:
        for k, v in q.group_by(func.date(order_dt)).order_by(func.date(order_dt)).all():
            if isinstance(k, datetime):
                k = k.date()
            if isinstance(k, date):
                out[k] = _money2(v)
    except Exception:
        return {}
    return out


def _bucketize_daily(series: Dict[date, float], bucket: str) -> Dict[date, float]:
    out: Dict[date, float] = {}
    for d, v in series.items():
        b = _bucket_key(bucket, d)
        out[b] = _money2(out.get(b, 0.0) + _safe_float(v))
    return out


def _gap_fill_series(
    bucket: str,
    start_date: date,
    end_date: date,
    series_bucketed: Dict[date, float],
) -> List[Dict[str, Any]]:
    step = _stepper(bucket)
    cur = start_date
    rows: List[Dict[str, Any]] = []
    while cur <= end_date:
        rows.append(
            {
                "date": cur.isoformat(),
                "date_display": _ddmmyyyy(cur),
                "value": _money2(series_bucketed.get(cur, 0.0)),
            }
        )
        cur = step(cur)
    return rows


# ----------------------------- computation blocks -------------------------
def _compute_stock_block(farmer_id: UUID) -> Tuple[Dict[str, Any], int, int, int]:
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    qty_col = _product_qty_col()

    product_count = low_stock = out_of_stock = 0
    try:
        product_count = (
            db.session.query(func.count(product_pk))
            .select_from(Product)
            .filter(owner_col == farmer_id)
            .scalar()
            or 0
        )
        if qty_col is not None:
            low_stock = (
                db.session.query(func.count(product_pk))
                .select_from(Product)
                .filter(owner_col == farmer_id)
                .filter(qty_col <= LOW_STOCK_THRESHOLD)
                .scalar()
                or 0
            )
            out_of_stock = (
                db.session.query(func.count(product_pk))
                .select_from(Product)
                .filter(owner_col == farmer_id)
                .filter(qty_col <= 0)
                .scalar()
                or 0
            )
    except Exception:
        product_count, low_stock, out_of_stock = 0, 0, 0

    stock_status = {
        "low": int(low_stock),
        "out": int(out_of_stock),
        "total": int(product_count),
        "low_threshold": LOW_STOCK_THRESHOLD,
        "label": f"{int(low_stock)} low out of {int(product_count)} (Low ≤ {LOW_STOCK_THRESHOLD})",
    }
    return stock_status, int(product_count), int(low_stock), int(out_of_stock)


def _compute_new_orders(farmer_id: UUID, since_dt: datetime) -> int:
    order_dt = _order_dt_col()
    if order_dt is None:
        return 0

    order_pk = _order_pk_col()
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()

    try:
        return int(
            db.session.query(func.count(func.distinct(order_pk)))
            .select_from(Order)
            .join(OrderItem, oi_order_id == order_pk)
            .join(Product, oi_product_id == product_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= since_dt)
            .scalar()
            or 0
        )
    except Exception:
        return 0


def _compute_paid_kpis(
    farmer_id: UUID,
    since_dt: datetime,
    month_start_dt: datetime,
) -> Tuple[float, float, float]:
    order_dt = _order_dt_col()
    if order_dt is None:
        return 0.0, 0.0, 0.0

    order_pk = _order_pk_col()
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()

    revenue_expr = _revenue_expr()
    paid_pred = _paid_predicate(order_pk)

    revenue_paid_total = items_sold_paid = revenue_paid_this_month = 0.0
    try:
        revenue_paid_total = (
            db.session.query(func.coalesce(func.sum(revenue_expr), 0))
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .join(Order, oi_order_id == order_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= since_dt)
            .filter(paid_pred)
            .scalar()
            or 0
        )
        items_sold_paid = (
            db.session.query(func.coalesce(func.sum(getattr(OrderItem, "quantity")), 0))
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .join(Order, oi_order_id == order_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= since_dt)
            .filter(paid_pred)
            .scalar()
            or 0
        )
        revenue_paid_this_month = (
            db.session.query(func.coalesce(func.sum(revenue_expr), 0))
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .join(Order, oi_order_id == order_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= month_start_dt)
            .filter(paid_pred)
            .scalar()
            or 0
        )
    except Exception:
        return 0.0, 0.0, 0.0

    return float(revenue_paid_total or 0), float(items_sold_paid or 0), float(revenue_paid_this_month or 0)


def _compute_qoq_block(farmer_id: UUID, now: datetime) -> Dict[str, Any]:
    """
    QoQ totals are independent of the requested 'days' window.
    Current quarter vs previous quarter, PAID only.
    """
    order_dt = _order_dt_col()
    if order_dt is None:
        return {"current_quarter_total": 0.0, "previous_quarter_total": 0.0, "delta_pct": None}

    order_pk = _order_pk_col()
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()
    revenue_expr = _revenue_expr()
    paid_pred = _paid_predicate(order_pk)

    today = now.date()
    q_start = _quarter_start(today)
    prev_q_start = _add_quarters(q_start, -1)

    q_start_dt = datetime.combine(q_start, time.min)
    prev_q_start_dt = datetime.combine(prev_q_start, time.min)
    prev_q_end_dt = q_start_dt

    try:
        curr_q_total = (
            db.session.query(func.coalesce(func.sum(revenue_expr), 0))
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .join(Order, oi_order_id == order_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= q_start_dt)
            .filter(paid_pred)
            .scalar()
            or 0
        )
        prev_q_total = (
            db.session.query(func.coalesce(func.sum(revenue_expr), 0))
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .join(Order, oi_order_id == order_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= prev_q_start_dt)
            .filter(order_dt < prev_q_end_dt)
            .filter(paid_pred)
            .scalar()
            or 0
        )
        return {
            "current_quarter_start": q_start.isoformat(),
            "current_quarter_start_display": _ddmmyyyy(q_start),
            "previous_quarter_start": prev_q_start.isoformat(),
            "previous_quarter_start_display": _ddmmyyyy(prev_q_start),
            "current_quarter_total": _money2(curr_q_total),
            "previous_quarter_total": _money2(prev_q_total),
            "delta_pct": _pct_change(_safe_float(curr_q_total), _safe_float(prev_q_total)),
        }
    except Exception:
        return {"current_quarter_total": 0.0, "previous_quarter_total": 0.0, "delta_pct": None}


def _compute_yoy_block(
    farmer_id: UUID,
    revenue_paid_total: float,
    since_dt: datetime,
    now: datetime,
) -> Dict[str, Any]:
    """
    YoY totals: same window last year (365d shift), PAID only.
    (Tiles remain based on "days" window; trend window is handled separately.)
    """
    order_dt = _order_dt_col()
    if order_dt is None:
        return {"prev_year_window_total": 0.0, "delta_pct": None}

    year_shift = timedelta(days=365)
    since_dt_yoy = since_dt - year_shift
    now_yoy = now - year_shift

    order_pk = _order_pk_col()
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()
    revenue_expr = _revenue_expr()
    paid_pred = _paid_predicate(order_pk)

    try:
        prev_year_total = (
            db.session.query(func.coalesce(func.sum(revenue_expr), 0))
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .join(Order, oi_order_id == order_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= since_dt_yoy)
            .filter(order_dt <= now_yoy)
            .filter(paid_pred)
            .scalar()
            or 0
        )
        return {
            "prev_year_window_total": _money2(prev_year_total),
            "delta_pct": _pct_change(_safe_float(revenue_paid_total), _safe_float(prev_year_total)),
            "window_start_prev_year": _dt_iso(since_dt_yoy),
            "window_end_prev_year": _dt_iso(now_yoy),
            "window_start_prev_year_display": _ddmmyyyy(since_dt_yoy),
            "window_end_prev_year_display": _ddmmyyyy(now_yoy),
        }
    except Exception:
        return {"prev_year_window_total": 0.0, "delta_pct": None}


def _compute_trend_series(
    farmer_id: UUID,
    days: int,
    bucket: str,
    include_compare: bool,
    trend_start_date: Optional[date] = None,
    trend_end_date: Optional[date] = None,
) -> Tuple[List[Dict[str, Any]], Optional[List[Dict[str, Any]]], Dict[str, Any]]:
    """
    Trend window:
      - If trend_start_date & trend_end_date provided -> calendar window (Trend + Recent Orders ONLY)
      - Else -> last X days (same as tiles)
    """
    now = _utc_now()

    if trend_start_date and trend_end_date:
        window_start = trend_start_date
        window_end = trend_end_date
        window_mode = "calendar"
    else:
        window_end = now.date()
        window_start = window_end - timedelta(days=max(1, days) - 1)
        window_mode = "range"

    start_bucket = _bucket_start_for_window(bucket, window_start)

    dt_min, dt_max_excl = _window_dt(window_start, window_end)

    daily = _daily_revenue_series(farmer_id, dt_min=dt_min, dt_max_excl=dt_max_excl)
    bucketed = _bucketize_daily(daily, bucket=bucket)
    trend = _gap_fill_series(bucket=bucket, start_date=start_bucket, end_date=window_end, series_bucketed=bucketed)

    trend_yoy: Optional[List[Dict[str, Any]]] = None
    if include_compare:
        # Same calendar window last year (safe for Feb 29)
        yoy_start = _shift_year_safe(window_start, -1)
        yoy_end = _shift_year_safe(window_end, -1)

        yoy_start_bucket = _bucket_start_for_window(bucket, yoy_start)
        dt_min_y, dt_max_excl_y = _window_dt(yoy_start, yoy_end)

        daily_y = _daily_revenue_series(farmer_id, dt_min=dt_min_y, dt_max_excl=dt_max_excl_y)
        bucketed_y = _bucketize_daily(daily_y, bucket=bucket)
        trend_yoy = _gap_fill_series(
            bucket=bucket, start_date=yoy_start_bucket, end_date=yoy_end, series_bucketed=bucketed_y
        )

    window_meta = {
        "mode": window_mode,
        "trend_start_date": window_start.isoformat(),
        "trend_end_date": window_end.isoformat(),
        "trend_start_date_display": _ddmmyyyy(window_start),
        "trend_end_date_display": _ddmmyyyy(window_end),
    }

    return trend, trend_yoy, window_meta


def _compute_forecast(trend: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    values = [_safe_float(p.get("value")) for p in trend if _safe_float(p.get("value")) > 0]
    avg = round(sum(values) / len(values), 2) if values else 0.0
    return [{"date": "forecast", "date_display": None, "value": avg}]


def _compute_top_products(
    farmer_id: UUID,
    since_dt: datetime,
    top_limit: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    order_dt = _order_dt_col()
    if order_dt is None:
        return [], []

    order_pk = _order_pk_col()
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    product_name_col = _product_name_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()

    revenue_expr = _revenue_expr()
    paid_pred = _paid_predicate(order_pk)

    try:
        base_q = (
            db.session.query(
                product_pk.label("product_id"),
                product_name_col.label("product_name"),
                func.coalesce(func.sum(revenue_expr), 0).label("revenue"),
                func.coalesce(func.sum(getattr(OrderItem, "quantity")), 0).label("qty_sold"),
                func.count(func.distinct(order_pk)).label("order_count"),
            )
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .join(Order, oi_order_id == order_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= since_dt)
            .filter(paid_pred)
            .group_by(product_pk, product_name_col)
        )

        rev_rows = base_q.order_by(desc("revenue"), desc("qty_sold")).limit(top_limit).all()
        qty_rows = base_q.order_by(desc("qty_sold"), desc("revenue")).limit(top_limit).all()

        top_by_rev = [
            {
                "product_id": str(r.product_id),
                "product_name": str(r.product_name or "Product"),
                "revenue": _money2(r.revenue),
                "qty_sold": round(_safe_float(r.qty_sold), 3),
                "order_count": int(r.order_count or 0),
            }
            for r in rev_rows
        ]
        top_by_qty = [
            {
                "product_id": str(r.product_id),
                "product_name": str(r.product_name or "Product"),
                "revenue": _money2(r.revenue),
                "qty_sold": round(_safe_float(r.qty_sold), 3),
                "order_count": int(r.order_count or 0),
            }
            for r in qty_rows
        ]
        return top_by_rev, top_by_qty
    except Exception:
        return [], []


def _recent_order_ids(
    farmer_id: UUID,
    since_dt: datetime,
    until_excl_dt: Optional[datetime],
    limit: int,
) -> List[UUID]:
    """
    PAID ONLY.
    Window used here is the Trend window (if provided) or Range window (days).
    """
    order_dt = _order_dt_col()
    if order_dt is None:
        return []

    order_pk = _order_pk_col()
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()

    paid_pred = _paid_predicate(order_pk)

    try:
        q = (
            db.session.query(order_pk.label("oid"), func.max(order_dt).label("last_dt"))
            .select_from(Order)
            .join(OrderItem, oi_order_id == order_pk)
            .join(Product, oi_product_id == product_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= since_dt)
            .filter(paid_pred)
        )
        if until_excl_dt is not None:
            q = q.filter(order_dt < until_excl_dt)

        rows = q.group_by(order_pk).order_by(desc("last_dt")).limit(limit).all()

        out: List[UUID] = []
        for oid, _ in rows:
            if isinstance(oid, UUID):
                out.append(oid)
            else:
                u = _to_uuid(oid)
                if u:
                    out.append(u)
        return out
    except Exception:
        return []


def _farmer_subtotals_for_orders(farmer_id: UUID, order_ids: List[UUID]) -> Dict[str, float]:
    if not order_ids:
        return {}

    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()
    revenue_expr = _revenue_expr()

    try:
        rows = (
            db.session.query(
                oi_order_id.label("oid"),
                func.coalesce(func.sum(revenue_expr), 0).label("subtotal"),
            )
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .filter(owner_col == farmer_id)
            .filter(oi_order_id.in_(order_ids))
            .group_by(oi_order_id)
            .all()
        )
        return {str(r.oid): _money2(r.subtotal) for r in rows}
    except Exception:
        return {}


def _items_progress_for_orders(farmer_id: UUID, order_ids: List[UUID]) -> Dict[str, Dict[str, Any]]:
    """
    Partial delivery UI sync (best-effort):
    - Uses item delivery fields if present.
    - Filters items to farmer-owned products.
    """
    if not order_ids:
        return {}

    has_delivery_fields = any(
        hasattr(OrderItem, c)
        for c in ("delivered_qty", "delivered_quantity", "delivery_status", "item_delivery_status")
    )
    if not has_delivery_fields:
        return {}

    product_pk = _product_pk_col()
    owner_col = _product_owner_col()

    try:
        items = (
            db.session.query(OrderItem)
            .select_from(OrderItem)
            .filter(_oi_order_id_col().in_(order_ids))
            .all()
        )
    except Exception:
        return {}

    # Build product-owner map so we only count farmer items
    prod_ids: List[Any] = []
    for it in items:
        pid = getattr(it, "product_id", None) or getattr(it, "productId", None)
        if pid is not None:
            prod_ids.append(pid)

    prod_owner: Dict[str, str] = {}
    if prod_ids:
        try:
            rows = (
                db.session.query(product_pk, owner_col)
                .select_from(Product)
                .filter(product_pk.in_(prod_ids))
                .all()
            )
            prod_owner = {str(pid): str(own) for pid, own in rows}
        except Exception:
            prod_owner = {}

    out: Dict[str, Dict[str, Any]] = {}
    for it in items:
        oidv = getattr(it, "order_id", None) or getattr(it, "orderId", None)
        pidv = getattr(it, "product_id", None) or getattr(it, "productId", None)
        if oidv is None or pidv is None:
            continue
        if prod_owner and prod_owner.get(str(pidv)) != str(farmer_id):
            continue

        key = str(oidv)
        slot = out.setdefault(key, {"total_items": 0, "delivered_items": 0, "progress_pct": 0, "status": "pending"})
        slot["total_items"] += 1

        qty = _safe_float(getattr(it, "quantity", 0) or 0)
        delivered_qty = _safe_float(getattr(it, "delivered_qty", None) or getattr(it, "delivered_quantity", None) or 0)
        st = str(getattr(it, "delivery_status", "") or getattr(it, "item_delivery_status", "") or "").strip().lower()

        delivered = (st == "delivered") or (qty > 0 and delivered_qty >= qty)
        if delivered:
            slot["delivered_items"] += 1
        elif delivered_qty > 0 or st in {"partial", "in_transit"}:
            slot["status"] = "partial"

    for _k, v in out.items():
        t = int(v.get("total_items") or 0)
        d = int(v.get("delivered_items") or 0)
        if t > 0:
            v["progress_pct"] = int(round((d / t) * 100))
            if d >= t:
                v["status"] = "delivered"
            elif d > 0 or v.get("status") == "partial":
                v["status"] = "partial"
            else:
                v["status"] = "pending"

    return out


def _fetch_orders_with_buyer(order_ids: List[UUID]) -> List[Tuple[Any, Any, Any, Any]]:
    if not order_ids:
        return []

    order_pk = _order_pk_col()
    buyer_id_col = _order_buyer_id_col()

    try:
        if buyer_id_col is not None:
            name_expr = _user_name_expr().label("buyer_name")
            phone_expr = _user_phone_expr().label("buyer_phone")
            location_expr = _user_location_expr().label("buyer_location")

            return (
                db.session.query(Order, name_expr, phone_expr, location_expr)
                .join(User, User.id == buyer_id_col, isouter=True)
                .filter(order_pk.in_(order_ids))
                .all()
            )

        rows = db.session.query(Order).filter(order_pk.in_(order_ids)).all()
        return [(o, None, None, None) for o in rows]
    except Exception:
        return []


def _compute_recent_orders(
    farmer_id: UUID,
    since_dt: datetime,
    until_excl_dt: Optional[datetime],
    recent_limit: int,
) -> List[Dict[str, Any]]:
    order_ids = _recent_order_ids(farmer_id, since_dt, until_excl_dt, recent_limit)
    if not order_ids:
        return []

    pk_attr = _order_pk_attr_name()
    idx = {str(oid): i for i, oid in enumerate(order_ids)}

    payments = _payments_map_for_orders(order_ids)
    subtotals = _farmer_subtotals_for_orders(farmer_id, order_ids)
    progress = _items_progress_for_orders(farmer_id, order_ids)
    rows = _fetch_orders_with_buyer(order_ids)

    def _order_id_str(o: Any) -> str:
        try:
            v = getattr(o, pk_attr, None)
            return str(v) if v is not None else ""
        except Exception:
            return ""

    rows.sort(key=lambda r: idx.get(_order_id_str(r[0]), 10**9))

    out: List[Dict[str, Any]] = []
    for o, buyer_name, buyer_phone, buyer_location in rows:
        oid_s = _order_id_str(o) or None
        pm = payments.get(oid_s or "", {}) if oid_s else {}
        payment_status = str(pm.get("payment_status", "unpaid") or "unpaid").lower()
        payment_locked = payment_status == "refunded"

        odt = getattr(o, "order_date", None) or getattr(o, "created_at", None)
        exp = getattr(o, "expected_delivery_date", None)

        out.append(
            {
                "order_id": oid_s,
                "order_date": _dt_iso(odt),
                "order_date_display": _ddmmyyyy(odt),
                "status": str(getattr(o, "status", "") or ""),
                "delivery_status": str(getattr(o, "delivery_status", "") or ""),
                "delivery_method": str(getattr(o, "delivery_method", "") or ""),
                "delivery_address": getattr(o, "delivery_address", None),
                "expected_delivery_date": _date_iso(exp),
                "expected_delivery_date_display": _ddmmyyyy(exp),
                "order_total": _money2(getattr(o, "order_total", 0) or 0),
                "farmer_subtotal": _money2(subtotals.get(oid_s or "", 0.0)),
                "buyer": {
                    "name": str(buyer_name) if buyer_name is not None else None,
                    "phone": str(buyer_phone) if buyer_phone is not None else None,
                    "location": str(buyer_location) if buyer_location is not None else None,
                },
                "payment_status": payment_status,
                "payment_method": pm.get("payment_method"),
                "payment_reference": pm.get("payment_reference"),
                "paid_at": pm.get("paid_at"),
                "paid_at_display": pm.get("paid_at_display"),
                "payment_locked": payment_locked,
                "items_progress": progress.get(oid_s or "", None),
            }
        )
    return out


def _compute_farmer_rank(
    farmer_id: UUID,
    since_dt: datetime,
) -> Dict[str, Any]:
    """
    Ranking = orders_received (window) + avg_rating (window) weighted.
    Best-effort: returns "—" on any schema mismatch.
    """
    order_dt = _order_dt_col()
    if order_dt is None:
        return {"rank": None, "total": 0, "percentile": None, "label": "—"}

    order_pk = _order_pk_col()
    product_pk = _product_pk_col()
    owner_col = _product_owner_col()
    oi_order_id = _oi_order_id_col()
    oi_product_id = _oi_product_id_col()

    rank_basis = {"orders_weight": 1.0, "rating_weight": 2.0}
    total = 0

    try:
        all_farmer_ids = [str(x[0]) for x in db.session.query(User.id).filter(User.role == ROLE_FARMER).all()]
        total = len(all_farmer_ids)

        orders_rows = (
            db.session.query(owner_col.label("fid"), func.count(func.distinct(order_pk)).label("orders_received"))
            .select_from(Order)
            .join(OrderItem, oi_order_id == order_pk)
            .join(Product, oi_product_id == product_pk)
            .filter(order_dt >= since_dt)
            .group_by(owner_col)
            .all()
        )
        orders_map = {str(r.fid): int(r.orders_received or 0) for r in orders_rows}

        ratings_map: Dict[str, Dict[str, Any]] = {}
        try:
            from backend.models.rating import Rating

            score_col = getattr(Rating, "rating_score", None) or getattr(Rating, "score", None)
            created_col = getattr(Rating, "created_at", None)
            product_id_col = getattr(Rating, "product_id", None) or getattr(Rating, "productId", None)
            if score_col is not None and created_col is not None and product_id_col is not None:
                rrows = (
                    db.session.query(
                        owner_col.label("fid"),
                        func.coalesce(func.avg(score_col), 0).label("avg_rating"),
                        func.count().label("rating_count"),
                    )
                    .select_from(Rating)
                    .join(Product, product_id_col == product_pk)
                    .filter(created_col >= since_dt)
                    .group_by(owner_col)
                    .all()
                )
                ratings_map = {
                    str(r.fid): {"avg": float(r.avg_rating or 0), "count": int(r.rating_count or 0)} for r in rrows
                }
        except Exception:
            ratings_map = {}

        scores: List[Dict[str, Any]] = []
        for fid in all_farmer_ids:
            o_cnt = int(orders_map.get(fid, 0))
            r_avg = float(ratings_map.get(fid, {}).get("avg", 0.0))
            r_cnt = int(ratings_map.get(fid, {}).get("count", 0))
            score = (o_cnt * rank_basis["orders_weight"]) + (r_avg * rank_basis["rating_weight"])
            scores.append(
                {"fid": fid, "score": float(score), "orders_received": o_cnt, "avg_rating": r_avg, "rating_count": r_cnt}
            )

        scores.sort(key=lambda x: x["score"], reverse=True)

        me = str(farmer_id)
        if total and any(s["fid"] == me for s in scores):
            idx0 = next(i for i, s in enumerate(scores) if s["fid"] == me)
            rank = idx0 + 1
            percentile = round(1 - (idx0 / max(total, 1)), 4)
            label = f"Top {max(1, int(round((rank / total) * 100)))}%"

            mine = scores[idx0]
            return {
                "rank": rank,
                "total": total,
                "percentile": percentile,
                "label": label,
                "basis": {"orders_weight": rank_basis["orders_weight"], "rating_weight": rank_basis["rating_weight"]},
                "orders_received": int(mine.get("orders_received") or 0),
                "avg_rating_window": round(float(mine.get("avg_rating") or 0.0), 2),
                "rating_count_window": int(mine.get("rating_count") or 0),
            }

        return {"rank": None, "total": total, "percentile": None, "label": "—", "basis": rank_basis}
    except Exception:
        return {"rank": None, "total": 0, "percentile": None, "label": "—", "basis": rank_basis}


def _compute_ratings_summary(farmer_id: UUID, since_dt: datetime) -> Tuple[Optional[float], int, int]:
    """
    Returns: avg_rating, feedback_count, comment_count
    Best-effort (schema-safe).
    """
    try:
        from backend.models.rating import Rating

        product_pk = _product_pk_col()
        owner_col = _product_owner_col()

        score_col = getattr(Rating, "rating_score", None) or getattr(Rating, "score", None)
        created_col = getattr(Rating, "created_at", None)
        product_id_col = getattr(Rating, "product_id", None) or getattr(Rating, "productId", None)
        comments_col = getattr(Rating, "comments", None)

        if score_col is None or created_col is None or product_id_col is None:
            return None, 0, 0

        comment_sum = (
            func.coalesce(func.sum(case((comments_col.isnot(None), 1), else_=0)), 0) if comments_col is not None else 0
        )

        row = (
            db.session.query(func.coalesce(func.avg(score_col), 0), func.count(), comment_sum)
            .select_from(Rating)
            .join(Product, product_id_col == product_pk)
            .filter(owner_col == farmer_id)
            .filter(created_col >= since_dt)
            .first()
        )
        if not row:
            return None, 0, 0

        avg_rating = round(float(row[0] or 0), 2)
        feedback_count = int(row[1] or 0)
        comment_count = int(row[2] or 0) if comments_col is not None else 0
        return avg_rating, feedback_count, comment_count
    except Exception:
        return None, 0, 0


def _compute_overview_payload(
    farmer_id: UUID,
    days: int,
    bucket: str,
    top_limit: int,
    recent_limit: int,
    include_compare: bool,
    trend_start_date: Optional[date],
    trend_end_date: Optional[date],
) -> Dict[str, Any]:
    now = _utc_now()

    order_dt = _order_dt_col()
    if order_dt is None:
        return {"success": False, "message": "Order schema mismatch (missing order_date/created_at)"}

    # ----------------------------------------------------------------------------
    # KPI window (controls ALL tiles except Trend+Recent Orders)
    # ----------------------------------------------------------------------------
    kpi_end = now.date()
    kpi_start = kpi_end - timedelta(days=max(1, days) - 1)
    since_dt = datetime.combine(kpi_start, time.min)
    prev_since_dt = since_dt - timedelta(days=max(1, days))
    month_start_dt = datetime(now.year, now.month, 1)

    # ----------------------------------------------------------------------------
    # Trend/Recent Orders window (calendar window OPTIONAL; applies ONLY to those)
    # ----------------------------------------------------------------------------
    if trend_start_date and trend_end_date:
        trend_start = trend_start_date
        trend_end = trend_end_date
    else:
        trend_start = kpi_start
        trend_end = kpi_end

    trend_since_dt, trend_until_excl = _window_dt(trend_start, trend_end)

    # Stock
    stock_status, product_count, low_stock, out_of_stock = _compute_stock_block(farmer_id)

    # KPIs
    new_orders = _compute_new_orders(farmer_id, since_dt)
    revenue_paid_total, items_sold_paid, revenue_paid_this_month = _compute_paid_kpis(farmer_id, since_dt, month_start_dt)

    # Previous window delta (based on KPI window)
    prev_total = 0.0
    window_delta_pct: Optional[float] = None
    try:
        order_pk = _order_pk_col()
        product_pk = _product_pk_col()
        owner_col = _product_owner_col()
        oi_order_id = _oi_order_id_col()
        oi_product_id = _oi_product_id_col()
        revenue_expr = _revenue_expr()
        paid_pred = _paid_predicate(order_pk)

        prev_total = (
            db.session.query(func.coalesce(func.sum(revenue_expr), 0))
            .select_from(OrderItem)
            .join(Product, oi_product_id == product_pk)
            .join(Order, oi_order_id == order_pk)
            .filter(owner_col == farmer_id)
            .filter(order_dt >= prev_since_dt)
            .filter(order_dt < since_dt)
            .filter(paid_pred)
            .scalar()
            or 0
        )
        window_delta_pct = _pct_change(_safe_float(revenue_paid_total), _safe_float(prev_total))
    except Exception:
        prev_total, window_delta_pct = 0.0, None

    # QoQ + YoY blocks (tiles window)
    qoq = _compute_qoq_block(farmer_id, now)
    yoy = _compute_yoy_block(farmer_id, revenue_paid_total, since_dt, now)

    # Trend + YoY trend (trend window)
    revenue_trend, revenue_trend_prev_year, trend_window_meta = _compute_trend_series(
        farmer_id=farmer_id,
        days=days,
        bucket=bucket,
        include_compare=include_compare,
        trend_start_date=trend_start_date,
        trend_end_date=trend_end_date,
    )
    revenue_forecast = _compute_forecast(revenue_trend)

    # Top products (tiles window)
    top_products, top_products_by_qty = _compute_top_products(farmer_id, since_dt, top_limit)

    # Recent orders (trend window) — PAID ONLY enforced in query
    recent_orders = _compute_recent_orders(farmer_id, trend_since_dt, trend_until_excl, recent_limit)

    # Rank + ratings (tiles window)
    farmer_rank = _compute_farmer_rank(farmer_id, since_dt)
    avg_rating, feedback_count, comment_count = _compute_ratings_summary(farmer_id, since_dt)

    return {
        "success": True,
        "farmer_id": str(farmer_id),
        "days": days,
        "bucket": bucket,
        "bucket_options": ["day", "week", "month", "bimonth", "quarter", "year"],
        "kpi_window": {
            "start_date": kpi_start.isoformat(),
            "end_date": kpi_end.isoformat(),
            "start_date_display": _ddmmyyyy(kpi_start),
            "end_date_display": _ddmmyyyy(kpi_end),
        },
        # Window info for Trend/Recent Orders (UI label + exports)
        "trend_window": trend_window_meta,
        # KPIs
        "new_orders": int(new_orders),
        "revenue_paid_total": _money2(revenue_paid_total),
        "revenue_paid_this_month": _money2(revenue_paid_this_month),
        "items_sold_paid": round(_safe_float(items_sold_paid), 3),
        "items_sold_paid_display": _num_display(items_sold_paid, 3),
        # Compatibility aliases
        "revenue_total": _money2(revenue_paid_total),
        "items_sold": round(_safe_float(items_sold_paid), 3),
        # Window compare (tiles window)
        "revenue_prev_window": _money2(prev_total),
        "revenue_delta_pct": window_delta_pct,
        # QoQ + YoY blocks
        "qoq": qoq,
        "yoy": yoy,
        # Stock
        "product_count": int(product_count),
        "low_stock_count": int(low_stock),
        "out_of_stock_count": int(out_of_stock),
        "stock_status": stock_status,
        # Trend (paid-only)
        "revenue_trend": revenue_trend,
        "revenue_trend_prev_year": revenue_trend_prev_year,
        "revenue_forecast": revenue_forecast,
        # Top products (paid-only)
        "top_products": top_products,
        "top_products_by_qty": top_products_by_qty,
        # Recent orders (paid-only)
        "recent_orders": recent_orders,
        "recent": recent_orders,  # alias
        # Ratings
        "avg_rating": avg_rating,
        "feedback_count": int(feedback_count),
        "comment_count": int(comment_count),
        # Rank
        "farmer_rank": farmer_rank,
        "farmer_rank_label": farmer_rank.get("label", "—"),
        "farmer_rank_percentile": farmer_rank.get("percentile"),
    }


# ----------------------------- request parsing ----------------------------
def _parse_bucket(raw: Optional[str]) -> str:
    """
    Bucket parser (type-checker safe):
      - Flask request.args.get(...) returns Optional[str]
      - We accept Optional[str] and normalize to a supported bucket
    """
    b = str(raw or "week").strip().lower()

    if b in {"annual", "annually"}:
        b = "year"

    # quarterly synonyms
    if b in {"q", "quarterly"}:
        b = "quarter"

    # bi-monthly synonyms (every 2 months: Jan–Feb, Mar–Apr, ...)
    if b in {"bi-monthly", "bimonthly", "bi_monthly", "bi-month", "bi_month", "bimonth"}:
        b = "bimonth"

    if b not in {"day", "week", "month", "bimonth", "quarter", "year"}:
        b = "week"
    return b


def _resolve_farmer_id(user: User) -> Optional[UUID]:
    if user.role == ROLE_ADMIN:
        return _to_uuid(request.args.get("farmerId") or request.args.get("farmer_id"))

    uid = _to_uuid(getattr(user, "id", None)) or _to_uuid(getattr(user, "user_id", None))
    return uid


def _parse_bool(raw: Any, default: bool = True) -> bool:
    s = str(raw if raw is not None else ("1" if default else "0")).strip().lower()
    return s not in {"0", "false", "no", "off"}


def _parse_trend_window_args() -> Tuple[Optional[date], Optional[date]]:
    """
    Accepts:
      - trend_start_date / trend_end_date   (preferred)
    Also accepts legacy synonyms:
      - start_date / end_date
      - window_start_date / window_end_date
    """
    s = (
        request.args.get("trend_start_date")
        or request.args.get("start_date")
        or request.args.get("window_start_date")
    )
    e = (
        request.args.get("trend_end_date")
        or request.args.get("end_date")
        or request.args.get("window_end_date")
    )
    return _parse_date_yyyy_mm_dd(s), _parse_date_yyyy_mm_dd(e)


# -------------------------------- routes ----------------------------------
@farmers_bp.get("/me", strict_slashes=False)
@token_required
def farmer_me():
    user = _current_user()
    if not user:
        return _json_error("Unauthorized", 401)

    return jsonify(
        {
            "success": True,
            "farmer": {
                "id": str(user.id),
                "full_name": user.full_name,
                "email": user.email,
                "phone": user.phone,
                "location": user.location,
                "role": user.role,
            },
        }
    )


@farmers_bp.get("/overview", strict_slashes=False)
@token_required
def farmer_overview():
    """
    Params:
      - days (60)                     -> controls KPI tiles (snapshot window)
      - bucket=day|week|month|bimonth|quarter|year (default week)
      - farmerId (admin only)
      - top_limit (8)
      - recent_limit (8)
      - include_compare (1)           -> include YoY trend series
      - trend_start_date=YYYY-MM-DD   -> OPTIONAL calendar window
      - trend_end_date=YYYY-MM-DD     -> applies ONLY to:
                                        ✅ revenue_trend (paid)
                                        ✅ recent_orders (paid)
    """
    user = _current_user()
    if not user:
        return _json_error("Unauthorized", 401)
    if user.role not in (ROLE_ADMIN, ROLE_FARMER):
        return _json_error("Forbidden", 403)

    farmer_id = _resolve_farmer_id(user)
    if not farmer_id:
        return _json_error("Invalid farmer", 400)

    # extra safety for farmer role (no cross-access)
    if user.role == ROLE_FARMER:
        current_uid = _to_uuid(getattr(user, "id", None)) or _to_uuid(getattr(user, "user_id", None))
        if current_uid is None or str(current_uid) != str(farmer_id):
            return _json_error("Forbidden", 403)

    days = max(1, min(_safe_int(request.args.get("days", 60)), 365))
    bucket = _parse_bucket(request.args.get("bucket"))
    top_limit = max(1, min(_safe_int(request.args.get("top_limit", 8)), 20))
    recent_limit = max(4, min(_safe_int(request.args.get("recent_limit", 8)), 20))
    include_compare = _parse_bool(request.args.get("include_compare", "1"), default=True)

    trend_start_date, trend_end_date = _parse_trend_window_args()
    if (trend_start_date and not trend_end_date) or (trend_end_date and not trend_start_date):
        return _json_error("Provide BOTH trend_start_date and trend_end_date (YYYY-MM-DD).", 400)
    if trend_start_date and trend_end_date and trend_start_date > trend_end_date:
        return _json_error("trend_start_date must be <= trend_end_date.", 400)

    payload = _compute_overview_payload(
        farmer_id=farmer_id,
        days=days,
        bucket=bucket,
        top_limit=top_limit,
        recent_limit=recent_limit,
        include_compare=include_compare,
        trend_start_date=trend_start_date,
        trend_end_date=trend_end_date,
    )

    if not payload.get("success"):
        return _json_error(payload.get("message", "Failed"), 500)

    return jsonify(payload)


# ----------------------------- export helpers -----------------------------
def _pdf_export(payload: Dict[str, Any], section: str) -> BytesIO:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    w, h = A4

    y = h - 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, "AgroConnect Namibia — Farmer Overview Export")
    y -= 18
    c.setFont("Helvetica", 10)

    tw = payload.get("trend_window") or {}
    tw_label = ""
    if tw.get("trend_start_date") and tw.get("trend_end_date"):
        tw_label = f" • Trend window: {tw.get('trend_start_date_display')} → {tw.get('trend_end_date_display')}"

    c.drawString(
        40,
        y,
        f"Farmer: {payload.get('farmer_id')} • Days: {payload.get('days')} • Bucket: {payload.get('bucket')}{tw_label}",
    )
    y -= 22

    def line(txt: str, bold: bool = False):
        nonlocal y
        if y < 60:
            c.showPage()
            y = h - 40
        c.setFont("Helvetica-Bold" if bold else "Helvetica", 10)
        c.drawString(40, y, (txt or "")[:120])
        y -= 14

    if section in {"all", "kpis"}:
        line("KPIs", bold=True)
        line(f"New orders: {payload.get('new_orders')}")
        line(f"Revenue total (paid): N$ {payload.get('revenue_paid_total')}")
        line(f"Revenue this month (paid): N$ {payload.get('revenue_paid_this_month')}")
        line(f"Items sold (paid): {payload.get('items_sold_paid_display')}")
        line(
            f"Stock: low={payload.get('low_stock_count')} out={payload.get('out_of_stock_count')} total={payload.get('product_count')}"
        )
        y -= 6

    if section in {"all", "trend"}:
        line("Revenue Trend (Paid)", bold=True)
        for p in (payload.get("revenue_trend") or [])[:40]:
            line(f"{p.get('date_display') or p.get('date')}: N$ {p.get('value')}")
        y -= 6

    if section in {"all", "top_products"}:
        line("Top Products (by revenue)", bold=True)
        for p in (payload.get("top_products") or [])[:20]:
            line(
                f"{p.get('product_name')}: N$ {p.get('revenue')} • Qty {p.get('qty_sold')} • Orders {p.get('order_count')}"
            )
        y -= 6

    if section in {"all", "orders"}:
        line("Recent Orders (Paid only)", bold=True)
        for o in (payload.get("recent_orders") or [])[:20]:
            buyer = (o.get("buyer") or {}).get("name") or "Customer"
            loc = (o.get("buyer") or {}).get("location") or ""
            line(
                f"{o.get('order_id')} • {o.get('order_date_display')} • {buyer} {('('+loc+')') if loc else ''} • {o.get('payment_status')} • {o.get('delivery_status')}"
            )

    c.showPage()
    c.save()
    buf.seek(0)
    return buf


def _csv_export(payload: Dict[str, Any], section: str, include_compare: bool) -> BytesIO:
    out = StringIO()
    writer = csv.writer(out)

    def blank():
        writer.writerow([])

    if section in {"all", "kpis"}:
        writer.writerow(["KPIs"])
        writer.writerow(["New orders", payload.get("new_orders")])
        writer.writerow(["Revenue total (paid)", payload.get("revenue_paid_total")])
        writer.writerow(["Revenue this month (paid)", payload.get("revenue_paid_this_month")])
        writer.writerow(["Items sold (paid)", payload.get("items_sold_paid_display")])
        writer.writerow(["Low stock", payload.get("low_stock_count")])
        writer.writerow(["Out of stock", payload.get("out_of_stock_count")])
        writer.writerow(["Product count", payload.get("product_count")])
        blank()

    if section in {"all", "trend"}:
        tw = payload.get("trend_window") or {}
        if tw.get("trend_start_date") and tw.get("trend_end_date"):
            writer.writerow(
                ["Trend window (DD-MM-YYYY)", f"{tw.get('trend_start_date_display')} → {tw.get('trend_end_date_display')}"]
            )
            blank()

        writer.writerow(["Revenue Trend (Paid)"])
        writer.writerow(["Date (DD-MM-YYYY)", "Date (ISO)", "Value"])
        for p in payload.get("revenue_trend") or []:
            writer.writerow([p.get("date_display") or "", p.get("date") or "", p.get("value") or 0])
        blank()

        if include_compare and payload.get("revenue_trend_prev_year"):
            writer.writerow(["Revenue Trend Prev Year (Paid)"])
            writer.writerow(["Date (DD-MM-YYYY)", "Date (ISO)", "Value"])
            for p in payload.get("revenue_trend_prev_year") or []:
                writer.writerow([p.get("date_display") or "", p.get("date") or "", p.get("value") or 0])
            blank()

    if section in {"all", "top_products"}:
        writer.writerow(["Top Products (By Revenue)"])
        writer.writerow(["Product", "Revenue", "Qty Sold", "Order Count"])
        for p in payload.get("top_products") or []:
            writer.writerow([p.get("product_name"), p.get("revenue"), p.get("qty_sold"), p.get("order_count")])
        blank()

        writer.writerow(["Top Products (By Quantity)"])
        writer.writerow(["Product", "Revenue", "Qty Sold", "Order Count"])
        for p in payload.get("top_products_by_qty") or []:
            writer.writerow([p.get("product_name"), p.get("revenue"), p.get("qty_sold"), p.get("order_count")])
        blank()

    if section in {"all", "orders"}:
        writer.writerow(["Recent Orders (Paid only)"])
        writer.writerow(
            [
                "Order ID",
                "Order Date (DD-MM-YYYY)",
                "Buyer",
                "Buyer Location",
                "Delivery Address",
                "Payment Status",
                "Delivery Status",
                "Farmer Subtotal",
            ]
        )
        for o in payload.get("recent_orders") or []:
            buyer = (o.get("buyer") or {}).get("name") or ""
            loc = (o.get("buyer") or {}).get("location") or ""
            writer.writerow(
                [
                    o.get("order_id"),
                    o.get("order_date_display") or "",
                    buyer,
                    loc,
                    o.get("delivery_address") or "",
                    o.get("payment_status") or "",
                    o.get("delivery_status") or "",
                    o.get("farmer_subtotal") or 0,
                ]
            )
        blank()

    data = out.getvalue().encode("utf-8")
    buf = BytesIO(data)
    buf.seek(0)
    return buf


@farmers_bp.get("/overview/export", strict_slashes=False)
@token_required
def farmer_overview_export():
    """
    Export like Power BI.

    Query:
      - format=csv|pdf (default csv)
      - section=all|kpis|trend|orders|top_products (default all)
      - days, bucket, farmerId (admin), top_limit, recent_limit, include_compare
      - trend_start_date=YYYY-MM-DD, trend_end_date=YYYY-MM-DD (optional; trend+recent only)
    """
    user = _current_user()
    if not user:
        return _json_error("Unauthorized", 401)
    if user.role not in (ROLE_ADMIN, ROLE_FARMER):
        return _json_error("Forbidden", 403)

    farmer_id = _resolve_farmer_id(user)
    if not farmer_id:
        return _json_error("Invalid farmer", 400)

    if user.role == ROLE_FARMER:
        current_uid = _to_uuid(getattr(user, "id", None)) or _to_uuid(getattr(user, "user_id", None))
        if current_uid is None or str(current_uid) != str(farmer_id):
            return _json_error("Forbidden", 403)

    fmt = str(request.args.get("format") or "csv").strip().lower()
    section = str(request.args.get("section") or "all").strip().lower()

    days = max(1, min(_safe_int(request.args.get("days", 60)), 365))
    bucket = _parse_bucket(request.args.get("bucket"))
    top_limit = max(1, min(_safe_int(request.args.get("top_limit", 8)), 20))
    recent_limit = max(4, min(_safe_int(request.args.get("recent_limit", 8)), 20))
    include_compare = _parse_bool(request.args.get("include_compare", "1"), default=True)

    trend_start_date, trend_end_date = _parse_trend_window_args()
    if (trend_start_date and not trend_end_date) or (trend_end_date and not trend_start_date):
        return _json_error("Provide BOTH trend_start_date and trend_end_date (YYYY-MM-DD).", 400)
    if trend_start_date and trend_end_date and trend_start_date > trend_end_date:
        return _json_error("trend_start_date must be <= trend_end_date.", 400)

    payload = _compute_overview_payload(
        farmer_id=farmer_id,
        days=days,
        bucket=bucket,
        top_limit=top_limit,
        recent_limit=recent_limit,
        include_compare=include_compare,
        trend_start_date=trend_start_date,
        trend_end_date=trend_end_date,
    )

    if not payload.get("success"):
        return _json_error(payload.get("message", "Failed"), 500)

    if fmt == "pdf":
        try:
            buf = _pdf_export(payload, section=section)
        except Exception:
            return _json_error("PDF export requires reportlab (pip install reportlab). Use format=csv instead.", 501)

        filename = f"farmer_overview_{payload.get('farmer_id')}_{date.today().isoformat()}.pdf"
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)

    buf = _csv_export(payload, section=section, include_compare=include_compare)
    filename = f"farmer_overview_{payload.get('farmer_id')}_{date.today().isoformat()}.csv"
    return send_file(buf, mimetype="text/csv", as_attachment=True, download_name=filename)
