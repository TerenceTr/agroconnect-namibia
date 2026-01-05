# =====================================================================
# backend/mappers/product_mapper.py
# ---------------------------------------------------------------------
# FILE ROLE:
#   • Converts ORM Product → immutable ProductDTO (API/AI contract)
#   • Enforces presence of required fields (via require())
#   • Avoids hard-coupling to “nice-to-have” derived properties
#
# WHY YOUR ERROR HAPPENED:
#   Pyright/Pylance sometimes cannot “see” dynamically-derived SQLAlchemy
#   attributes/properties (or your local Product class may not define `location`).
#   Accessing product.location directly can therefore raise:
#     "Attribute 'location' is unknown"
#
# FIX:
#   Compute location safely using getattr() + farmer relationship fallback.
# =====================================================================

from __future__ import annotations

from typing import Optional

from backend.dto.product_dto import ProductDTO
from backend.mappers.base import mapper, require
from backend.models.product import Product


def _safe_product_name(product: Product) -> str:
    """
    Best-effort “display name” resolver.

    Supports both styles:
      • product.name (property alias)
      • product.product_name (column)
    """
    name = getattr(product, "name", None)
    if isinstance(name, str) and name.strip():
        return name

    name2 = getattr(product, "product_name", None)
    if isinstance(name2, str) and name2.strip():
        return name2

    # Let require() produce the clean error message
    return require(None, "name")  # type: ignore[return-value]


def _safe_location(product: Product) -> Optional[str]:
    """
    Resolve a Product "location" without relying on Product.location
    being declared on the ORM model (keeps Pyright clean).

    Priority:
      1) product.location (if it exists as a column/property)
      2) product.farmer.location (if farmer relationship is loaded/available)
    """
    loc = getattr(product, "location", None)
    if isinstance(loc, str) and loc.strip():
        return loc

    farmer = getattr(product, "farmer", None)
    farmer_loc = getattr(farmer, "location", None) if farmer is not None else None
    if isinstance(farmer_loc, str) and farmer_loc.strip():
        return farmer_loc

    return None


def _safe_farmer_id(product: Product):
    """
    Support both:
      • product.farmer_id  (preferred Python attribute)
      • product.user_id    (older schemas)
    """
    fid = getattr(product, "farmer_id", None)
    if fid is not None:
        return fid
    return getattr(product, "user_id", None)


@mapper
def product_to_dto(
    product: Product,
    *,
    average_rating: float | None = None,
    total_sales: int | None = None,
) -> ProductDTO:
    """
    Convert ORM Product → ProductDTO.

    Notes:
      • require() is used only for truly required fields.
      • Optional/derived fields (location) are resolved safely.
    """
    return ProductDTO(
        id=require(getattr(product, "id", None), "id"),
        name=require(_safe_product_name(product), "name"),
        category=getattr(product, "category", None),
        price=require(getattr(product, "price", None), "price"),
        location=_safe_location(product),
        farmer_id=require(_safe_farmer_id(product), "farmer_id"),
        average_rating=average_rating,
        total_sales=total_sales,
    )
