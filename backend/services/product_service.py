# ====================================================================
# backend/services/product_service.py — Product Query + DTO Factory (PYRIGHT-CLEAN)
# ====================================================================
# FILE ROLE:
#   • Query Product ORM rows (and aggregated metrics) for search/AI feeds
#   • Build ProductDTO objects (stable contract) for API/AI layers
#   • Never expose ORM objects to callers
#
# WHY THIS FILE IS UPDATED:
#   • Multi-item schema: Product sales are stored in order_items, NOT orders.
#     Therefore, joins must be:
#         products <- order_items -> orders
#     and NOT:
#         orders.product_id  (does not exist anymore)
#
# PYRIGHT NOTES:
#   • Product has no mapped column called "location" — location is derived from farmer (User.location).
#   • Product.name is a Python @property alias. It's fine for DTO display,
#     but DO NOT use it inside SQL expressions; use Product.product_name there.
# ====================================================================

from __future__ import annotations

from typing import List, Optional, Tuple

from sqlalchemy import and_, func
from sqlalchemy.orm import aliased

from backend.database.db import db
from backend.dto.product_dto import ProductDTO
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import User

# Rating is optional in your project; keep safe import to prevent crashes
try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]


# --------------------------------------------------------------------
# Safe helper: derive location from farmer (User.location)
# --------------------------------------------------------------------
def _derive_location(product: Product) -> Optional[str]:
    """
    Best-effort product location:
      • Prefer farmer.location if relationship is available
      • Never raise; return None if missing/unloaded/unavailable
    """
    try:
        farmer = getattr(product, "farmer", None)
        loc = getattr(farmer, "location", None) if farmer else None
        if isinstance(loc, str) and loc.strip():
            return loc.strip()
        return None
    except Exception:
        return None


def _safe_float(value: object) -> float:
    """Convert a value to float without ever throwing."""
    try:
        return float(value)  # type: ignore[arg-type]
    except Exception:
        return 0.0


def _normalize_query(q: str) -> str:
    return (q or "").strip()


def _available_status_value() -> str:
    """
    Centralizes what we consider "available".
    Your DB dump commonly uses 'available'.
    """
    return "available"


def _paid_or_completed_expr():
    """
    Define a 'sale' as:
      - payment_status == 'paid' OR
      - status == 'completed'
    Implemented using SQLAlchemy boolean operators (no or_ import required).
    """
    return (
        (func.lower(func.coalesce(Order.payment_status, "")) == "paid")
        | (func.lower(func.coalesce(Order.status, "")) == "completed")
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
    Convert Product ORM → ProductDTO (immutable contract).

    IMPORTANT:
      Do NOT use product.location directly — it's not a mapped column.
      Use 'location' passed in (from join) or derive from farmer relationship.
    """
    if location is None:
        location = _derive_location(product)

    # price in your model is Decimal; ensure float for DTO
    price_val = _safe_float(getattr(product, "price", 0) or 0)

    # Product.name is a Python @property alias -> product.product_name
    # OK for DTO display (not used in SQL)
    display_name = getattr(product, "name", None) or getattr(product, "product_name", "")

    return ProductDTO(
        id=product.id,  # UUID
        name=str(display_name),
        category=getattr(product, "category", None),
        price=price_val,
        location=location,
        farmer_id=product.farmer_id,
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

    Returns:
      List[ProductDTO] including:
        • average_rating (if Rating table exists)
        • total_sales    (count DISTINCT orders that included product AND are paid/completed)
        • location derived from farmer User (best-effort)

    Notes:
      • Uses OUTER JOINs so products appear even with zero ratings/orders.
      • Multi-item sales logic uses OrderItem (NOT Order.product_id).
    """
    _ = customer_id  # intentionally unused
    limit_n = max(int(limit or 30), 1)
    qtext = _normalize_query(query)

    # Aliased farmer join for clarity
    Farmer = aliased(User)

    # Treat sale orders as paid or completed
    paid_or_completed_expr = _paid_or_completed_expr()

    # -----------------------------
    # Base query: Product + Farmer location
    # Aggregates:
    #   - avg_rating (optional)
    #   - total_sales = count DISTINCT sale orders that contain the product
    #
    # Multi-item join path:
    #   Product <- OrderItem -> Order
    # -----------------------------
    if Rating is not None:
        stmt = (
            db.session.query(  # type: ignore[attr-defined]
                Product,
                Farmer.location.label("farmer_location"),
                func.avg(Rating.rating_score).label("avg_rating"),
                func.count(func.distinct(Order.id)).label("total_sales"),
            )
            .join(Farmer, Farmer.id == Product.farmer_id)
            .outerjoin(Rating, Rating.product_id == Product.id)
            .outerjoin(OrderItem, OrderItem.product_id == Product.id)
            .outerjoin(
                Order,
                and_(
                    Order.id == OrderItem.order_id,
                    paid_or_completed_expr,
                ),
            )
            .filter(Product.status == _available_status_value())
            .group_by(Product.id, Farmer.location)
            .order_by(Product.created_at.desc())
            .limit(limit_n)
        )
    else:
        stmt = (
            db.session.query(  # type: ignore[attr-defined]
                Product,
                Farmer.location.label("farmer_location"),
                func.count(func.distinct(Order.id)).label("total_sales"),
            )
            .join(Farmer, Farmer.id == Product.farmer_id)
            .outerjoin(OrderItem, OrderItem.product_id == Product.id)
            .outerjoin(
                Order,
                and_(
                    Order.id == OrderItem.order_id,
                    paid_or_completed_expr,
                ),
            )
            .filter(Product.status == _available_status_value())
            .group_by(Product.id, Farmer.location)
            .order_by(Product.created_at.desc())
            .limit(limit_n)
        )

    # Simple name search (SQL-safe): use mapped column, not Product.name property.
    if qtext:
        like = f"%{qtext}%"
        stmt = stmt.filter(Product.product_name.ilike(like))

    results: List[ProductDTO] = []

    if Rating is not None:
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
