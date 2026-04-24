# ====================================================================
# backend/services/product_service.py — Product Query + DTO Factory
# ====================================================================
# FILE ROLE:
#   • Query Product ORM rows (and aggregated metrics) for search / AI feeds
#   • Build ProductDTO objects (stable contract) for API / AI layers
#   • Never expose ORM objects directly to callers
#
# WHY THIS VERSION IS CORRECT:
#   ✅ FIXES the Pyright error:
#        Cannot access attribute "payment_status" for class "type[Order]"
#      because Order.payment_status is NOT a mapped column in the current
#      schema. Sales are now derived using:
#        • payments.status == 'paid'
#        • OR orders.status == 'completed'
#
#   ✅ Uses the real multi-item schema:
#        products <- order_items -> orders
#      and optionally payments -> orders for paid detection.
#
#   ✅ Uses schema-robust column helpers for environments that may expose:
#        Product.product_id or Product.id
#        Product.user_id or Product.farmer_id
#        Order.order_id or Order.id
#        User.id or User.user_id
#
#   ✅ Never uses Product.name inside SQL expressions.
#      Product.name may be a Python @property alias only.
#
# NOTES:
#   • Product location is derived from the farmer/user relationship.
#   • ProductDTO stays the single public contract returned by this service.
# ====================================================================

from __future__ import annotations

from typing import Any, List, Optional, Tuple

from sqlalchemy import and_, case, func, or_
from sqlalchemy.orm import aliased

from backend.database.db import db
from backend.dto.product_dto import ProductDTO
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import User

# --------------------------------------------------------------------
# Optional models
# --------------------------------------------------------------------
# Rating is optional in some project states. Keep safe import so this service
# never crashes if the ratings model/table is not currently wired.
try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]

# Payment is used to derive "paid" sales because Order has no payment_status
# mapped column in the current schema.
try:
    from backend.models.payment import Payment
except Exception:  # pragma: no cover
    Payment = None  # type: ignore[assignment]


# --------------------------------------------------------------------
# Generic safe helpers
# --------------------------------------------------------------------
def _get_attr(obj: Any, *names: str) -> Any:
    """
    Best-effort attribute reader.

    This keeps the service resilient across small schema/name differences.
    """
    for name in names:
        if hasattr(obj, name):
            return getattr(obj, name)
    return None


def _safe_float(value: object) -> float:
    """Convert to float without ever throwing."""
    try:
        return float(value)  # type: ignore[arg-type]
    except Exception:
        return 0.0


def _normalize_query(q: str) -> str:
    return (q or "").strip()


# --------------------------------------------------------------------
# Schema-robust column resolvers
# --------------------------------------------------------------------
def _product_pk_col() -> Any:
    return _get_attr(Product, "product_id", "id")


def _product_owner_col() -> Any:
    return _get_attr(Product, "user_id", "farmer_id")


def _product_name_col() -> Any:
    return _get_attr(Product, "product_name", "name")


def _product_created_col() -> Any:
    return _get_attr(Product, "created_at", "updated_at")


def _user_pk_col() -> Any:
    return _get_attr(User, "id", "user_id")


def _user_location_col() -> Any:
    return _get_attr(User, "location", "town", "city", "region")


def _order_pk_col() -> Any:
    return _get_attr(Order, "order_id", "id")


def _order_status_col() -> Any:
    return _get_attr(Order, "status")


def _order_item_order_fk_col() -> Any:
    return _get_attr(OrderItem, "order_id")


def _order_item_product_fk_col() -> Any:
    return _get_attr(OrderItem, "product_id")


def _payment_order_fk_col() -> Any:
    if Payment is None:
        return None
    return _get_attr(Payment, "order_id")


def _payment_status_col() -> Any:
    if Payment is None:
        return None
    return _get_attr(Payment, "status")


def _rating_product_fk_col() -> Any:
    if Rating is None:
        return None
    return _get_attr(Rating, "product_id")


def _rating_score_col() -> Any:
    if Rating is None:
        return None
    return _get_attr(Rating, "rating_score", "score")


# --------------------------------------------------------------------
# Safe helper: derive location from farmer/user relationship
# --------------------------------------------------------------------
def _derive_location(product: Product) -> Optional[str]:
    """
    Best-effort product location:
      • Prefer farmer/user relationship if available
      • Never raise; return None if missing/unloaded/unavailable
    """
    try:
        farmer = (
            getattr(product, "farmer", None)
            or getattr(product, "user", None)
            or getattr(product, "owner", None)
        )
        loc = getattr(farmer, "location", None) if farmer else None
        if isinstance(loc, str) and loc.strip():
            return loc.strip()
        return None
    except Exception:
        return None


# --------------------------------------------------------------------
# Business-rule helpers
# --------------------------------------------------------------------
def _available_status_value() -> str:
    """
    Centralizes what we consider publicly available.
    Your schema commonly uses 'available'.
    """
    return "available"


def _build_paid_orders_subquery() -> Any:
    """
    Build a one-row-per-order subquery that indicates whether an order has at
    least one payment row with status='paid'.

    WHY THIS EXISTS:
      The current schema stores payment status in the payments table, not on the
      orders table. This replaces any incorrect use of Order.payment_status.
    """
    payment_order_fk = _payment_order_fk_col()
    payment_status = _payment_status_col()

    if Payment is None or payment_order_fk is None or payment_status is None:
        return None

    return (
        db.session.query(  # type: ignore[attr-defined]
            payment_order_fk.label("order_id"),
            func.max(
                case(
                    (func.lower(func.coalesce(payment_status, "")) == "paid", 1),
                    else_=0,
                )
            ).label("has_paid"),
        )
        .group_by(payment_order_fk)
        .subquery()
    )


# --------------------------------------------------------------------
# DTO builder
# --------------------------------------------------------------------
def build_product_dto(
    *,
    product: Product,
    avg_rating: Optional[float] = None,
    total_sales: Optional[int] = None,
    location: Optional[str] = None,
) -> ProductDTO:
    """
    Convert Product ORM -> ProductDTO.

    IMPORTANT:
      • Do NOT use product.location directly — that is not part of the current
        mapped schema.
      • For display, Product.name may be a Python property alias. That is fine
        here because this is NOT a SQL expression.
    """
    if location is None:
        location = _derive_location(product)

    product_id = _get_attr(product, "product_id", "id")
    farmer_id = _get_attr(product, "user_id", "farmer_id")
    display_name = _get_attr(product, "name", "product_name") or ""
    category = _get_attr(product, "category")
    price_val = _safe_float(_get_attr(product, "price") or 0)

    return ProductDTO(
        id=product_id,
        name=str(display_name),
        category=category,
        price=price_val,
        location=location,
        farmer_id=farmer_id,
        average_rating=avg_rating,
        total_sales=total_sales,
    )


# --------------------------------------------------------------------
# Query: candidate products for AI & search
# --------------------------------------------------------------------
def get_candidate_products(
    *,
    customer_id: Optional[str] = None,  # kept for API compatibility (unused)
    query: str = "",
    limit: int = 30,
) -> List[ProductDTO]:
    """
    Candidate products for AI & search.

    Returns ProductDTO rows including:
      • average_rating (if Rating model/table exists)
      • total_sales    = count DISTINCT sale orders that included the product
      • location       derived from farmer User.location (best-effort)

    SALES DEFINITION:
      A sale is counted when:
        • there is a paid payment row for the order
          OR
        • the order status is completed

    IMPORTANT:
      Multi-item sales logic uses OrderItem (NOT Order.product_id).
    """
    _ = customer_id  # intentionally unused, preserved for compatibility

    limit_n = max(int(limit or 30), 1)
    qtext = _normalize_query(query)

    Farmer = aliased(User)

    product_pk = _product_pk_col()
    product_owner = _product_owner_col()
    product_name = _product_name_col()
    product_created = _product_created_col()

    user_pk = _user_pk_col()
    user_location = _user_location_col()

    order_pk = _order_pk_col()
    order_status = _order_status_col()

    order_item_order_fk = _order_item_order_fk_col()
    order_item_product_fk = _order_item_product_fk_col()

    if (
        product_pk is None
        or product_owner is None
        or product_name is None
        or user_pk is None
        or order_pk is None
        or order_status is None
        or order_item_order_fk is None
        or order_item_product_fk is None
    ):
        return []

    paid_orders_sq = _build_paid_orders_subquery()

    # ----------------------------------------------------------------
    # Sale-condition expression.
    # This is the core fix for the original Pyright/schema problem:
    # we DO NOT reference Order.payment_status because it does not exist.
    # ----------------------------------------------------------------
    if paid_orders_sq is not None:
        sale_condition = or_(
            paid_orders_sq.c.has_paid == 1,
            func.lower(func.coalesce(order_status, "")) == "completed",
        )
    else:
        sale_condition = func.lower(func.coalesce(order_status, "")) == "completed"

    sales_order_expr = case(
        (sale_condition, order_pk),
        else_=None,
    )

    farmer_location_expr = (
        user_location.label("farmer_location")
        if user_location is not None
        else func.null().label("farmer_location")
    )

    rating_product_fk = _rating_product_fk_col()
    rating_score = _rating_score_col()

    # ----------------------------------------------------------------
    # Build base query.
    # Product rows are left-joined to order_items/orders/payments so products
    # still appear even when they have zero sales.
    # ----------------------------------------------------------------
    if Rating is not None and rating_product_fk is not None and rating_score is not None:
        stmt = (
            db.session.query(  # type: ignore[attr-defined]
                Product,
                farmer_location_expr,
                func.avg(rating_score).label("avg_rating"),
                func.count(func.distinct(sales_order_expr)).label("total_sales"),
            )
            .join(Farmer, user_pk == product_owner)
            .outerjoin(Rating, rating_product_fk == product_pk)
            .outerjoin(OrderItem, order_item_product_fk == product_pk)
            .outerjoin(Order, order_pk == order_item_order_fk)
        )
    else:
        stmt = (
            db.session.query(  # type: ignore[attr-defined]
                Product,
                farmer_location_expr,
                func.count(func.distinct(sales_order_expr)).label("total_sales"),
            )
            .join(Farmer, user_pk == product_owner)
            .outerjoin(OrderItem, order_item_product_fk == product_pk)
            .outerjoin(Order, order_pk == order_item_order_fk)
        )

    if paid_orders_sq is not None:
        stmt = stmt.outerjoin(paid_orders_sq, paid_orders_sq.c.order_id == order_pk)

    stmt = stmt.filter(Product.status == _available_status_value())

    # SQL-safe name search: use mapped DB column, never Product.name property.
    if qtext:
        like = f"%{qtext}%"
        stmt = stmt.filter(product_name.ilike(like))

    # Group by Product PK + farmer location.
    # Postgres handles the remaining Product columns through PK functional
    # dependency, which keeps the ORM row materialization simple.
    stmt = stmt.group_by(product_pk, farmer_location_expr)

    # Order by strongest commercial signal first, then recency.
    total_sales_label = "total_sales"
    if Rating is not None and rating_product_fk is not None and rating_score is not None:
        stmt = stmt.order_by(
            func.count(func.distinct(sales_order_expr)).desc(),
            func.avg(rating_score).desc(),
            product_created.desc() if product_created is not None else product_name.asc(),
        )
    else:
        stmt = stmt.order_by(
            func.count(func.distinct(sales_order_expr)).desc(),
            product_created.desc() if product_created is not None else product_name.asc(),
        )

    stmt = stmt.limit(limit_n)

    results: List[ProductDTO] = []

    # ----------------------------------------------------------------
    # Execute + materialize DTOs.
    # ----------------------------------------------------------------
    if Rating is not None and rating_product_fk is not None and rating_score is not None:
        rows: List[Tuple[Product, Optional[str], Optional[float], int]] = stmt.all()  # type: ignore[assignment]
        for product, farmer_location, avg, sales in rows:
            loc = (
                farmer_location.strip()
                if isinstance(farmer_location, str) and farmer_location.strip()
                else _derive_location(product)
            )

            results.append(
                build_product_dto(
                    product=product,
                    avg_rating=round(float(avg), 2) if avg is not None else None,
                    total_sales=int(sales or 0),
                    location=loc,
                )
            )
    else:
        rows2: List[Tuple[Product, Optional[str], int]] = stmt.all()  # type: ignore[assignment]
        for product, farmer_location, sales in rows2:
            loc = (
                farmer_location.strip()
                if isinstance(farmer_location, str) and farmer_location.strip()
                else _derive_location(product)
            )

            results.append(
                build_product_dto(
                    product=product,
                    avg_rating=None,
                    total_sales=int(sales or 0),
                    location=loc,
                )
            )

    return results
