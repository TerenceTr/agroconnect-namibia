# ============================================================================
# backend/services/delivery_quote.py — Delivery Quote Engine (Backend-only)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Single source of truth for delivery quotes.
#   - Uses farmer-configured tiers (DB)
#   - Computes distance using static town coords (no Google Maps)
#   - Adds weight-based surcharge (optional)
#   - Enforces pickup-only products
#
# THIS VERSION FIXES:
#   ✅ Pyright errors from constructing FarmerDeliveryTier with keyword args
#   ✅ Keeps fallback tiers available without persisting them
#   ✅ Adds a few safe parsing guards for robustness
# ============================================================================

from __future__ import annotations

from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from sqlalchemy import select

from backend.database.db import db
from backend.models.farmer_delivery_tier import FarmerDeliveryTier
from backend.models.product import Product
from backend.models.user import User

# ---------------------------------------------------------------------------
# Static coordinates for approximate distance (extend as needed)
# (No external API / no Google Maps)
# ---------------------------------------------------------------------------
TOWNS = {
    "windhoek": (-22.5609, 17.0658),
    "swakopmund": (-22.6792, 14.5272),
    "walvis bay": (-22.9576, 14.5053),
    "oshakati": (-17.7883, 15.6996),
    "rundu": (-17.9190, 19.7660),
    "katima mulilo": (-17.5000, 24.2667),
    "keetmanshoop": (-26.5833, 18.1333),
}

# Default tiers if farmer has not configured any yet.
# Tuple shape:
#   (km_min, km_max, base_fee, included_kg, per_kg_fee, is_free)
DEFAULT_TIERS = [
    (0, 5, Decimal("0"), Decimal("0"), Decimal("0"), True),
    (6, 10, Decimal("30"), Decimal("10"), Decimal("2"), False),
    (11, 15, Decimal("60"), Decimal("10"), Decimal("2"), False),
    (16, 30, Decimal("100"), Decimal("10"), Decimal("3"), False),
    (31, 60, Decimal("150"), Decimal("10"), Decimal("3"), False),
    (61, 100, Decimal("180"), Decimal("10"), Decimal("4"), False),
    (101, 9999, Decimal("200"), Decimal("10"), Decimal("4"), False),
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _norm_town(value: str) -> str:
    return (value or "").strip().lower()


def _find_town(text: str) -> Optional[str]:
    normalized = _norm_town(text)
    for name in TOWNS.keys():
        if name in normalized:
            return name
    return None


def _to_decimal(value: Any, default: Decimal = Decimal("0")) -> Decimal:
    try:
        return Decimal(str(value))
    except Exception:
        return default


def _to_uuid(value: Any) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except Exception:
        return None


def _haversine_km(a: Tuple[float, float], b: Tuple[float, float]) -> float:
    import math

    earth_radius_km = 6371.0
    lat1, lon1 = map(math.radians, a)
    lat2, lon2 = map(math.radians, b)

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    x = (
        math.sin(dlat / 2) ** 2
        + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2) ** 2
    )
    return 2 * earth_radius_km * math.asin(math.sqrt(x))


def estimate_distance_km(farmer_location: str, delivery_address: str) -> Optional[float]:
    """
    Approximate distance by matching known towns in both strings.
    Returns None when either town cannot be inferred.
    """
    farmer_town = _find_town(farmer_location)
    delivery_town = _find_town(delivery_address)

    if not farmer_town or not delivery_town:
        return None

    return _haversine_km(TOWNS[farmer_town], TOWNS[delivery_town])


def _load_farmer_tiers(farmer_id: UUID) -> List[FarmerDeliveryTier]:
    """
    Load active farmer-configured delivery tiers from the database.
    """
    rows = (
        db.session.execute(
            select(FarmerDeliveryTier)
            .where(FarmerDeliveryTier.farmer_id == farmer_id)
            .where(FarmerDeliveryTier.active.is_(True))
            .order_by(FarmerDeliveryTier.km_min.asc())
        )
        .scalars()
        .all()
    )
    return list(rows)


def _fallback_tiers() -> List[FarmerDeliveryTier]:
    """
    Build non-persisted FarmerDeliveryTier-like objects from DEFAULT_TIERS.

    WHY THIS VERSION CHANGED:
    Pyright complained about:
      No parameter named "farmer_id"
      No parameter named "km_min"
      ...
    because SQLAlchemy models do not always expose typed __init__ keyword
    parameters to static analysis.

    Creating an empty instance and assigning attributes explicitly avoids
    those errors while preserving the exact runtime behavior we want.
    """
    tiers: List[FarmerDeliveryTier] = []

    for km_min, km_max, base_fee, included_kg, per_kg_fee, is_free in DEFAULT_TIERS:
        tier = FarmerDeliveryTier()

        # Dummy owner for fallback-only, non-persisted tier objects.
        tier.farmer_id = UUID(int=0)

        tier.km_min = int(km_min)
        tier.km_max = int(km_max)
        tier.base_fee = Decimal(base_fee)
        tier.included_kg = Decimal(included_kg)
        tier.per_kg_fee = Decimal(per_kg_fee)
        tier.is_free = bool(is_free)
        tier.active = True

        tiers.append(tier)

    return tiers


def _calc_weight_kg(items: List[Dict[str, Any]]) -> Decimal:
    """
    Estimate combined weight:
      - If item has weight_kg -> quantity * weight_kg
      - Else fallback: quantity (assumes kg-style quantity)
    """
    total = Decimal("0")

    for item in items:
        qty = _to_decimal(item.get("quantity"), Decimal("0"))
        weight_per_unit = _to_decimal(item.get("weight_kg"), Decimal("0"))

        total += qty * (weight_per_unit if weight_per_unit > 0 else Decimal("1"))

    return total


def quote_for_farmer(
    farmer_id: UUID,
    delivery_method: str,
    delivery_address: str,
    items: List[Dict[str, Any]],
    farmer_location: str,
) -> Dict[str, Any]:
    """
    Returns:
      {
        fee,
        distance_km,
        status,
        requires_pickup,
        breakdown
      }
    """
    # Pickup always costs N$0.
    if delivery_method == "pickup":
        return {
            "fee": Decimal("0"),
            "distance_km": None,
            "status": "pickup",
            "requires_pickup": False,
            "breakdown": None,
        }

    # Enforce pickup-only products.
    if any(bool(item.get("pickup_only")) for item in items):
        return {
            "fee": Decimal("0"),
            "distance_km": None,
            "status": "pickup_only",
            "requires_pickup": True,
            "breakdown": "Some products are pickup-only.",
        }

    distance = estimate_distance_km(farmer_location, delivery_address)
    tiers = _load_farmer_tiers(farmer_id) or _fallback_tiers()

    # If we cannot estimate distance, use the highest tier as a safe worst-case.
    if distance is None:
        selected_tier = tiers[-1]
        distance_val = None
    else:
        distance_val = float(distance)
        selected_tier = next(
            (
                tier
                for tier in tiers
                if float(tier.km_min) <= distance_val <= float(tier.km_max)
            ),
            tiers[-1],
        )

    weight_kg = _calc_weight_kg(items)

    # Fee formula:
    #   base_fee + per_kg_fee * max(0, weight - included_kg)
    extra_weight = max(Decimal("0"), weight_kg - Decimal(selected_tier.included_kg))
    fee = Decimal(selected_tier.base_fee) + Decimal(selected_tier.per_kg_fee) * extra_weight

    if bool(selected_tier.is_free) or fee <= Decimal("0"):
        fee = Decimal("0")
        status = "free"
    else:
        status = "quoted"

    return {
        "fee": fee,
        "distance_km": distance_val,
        "status": status,
        "requires_pickup": False,
        "breakdown": {
            "tier": f"{selected_tier.km_min}-{selected_tier.km_max}km",
            "base_fee": str(selected_tier.base_fee),
            "included_kg": str(selected_tier.included_kg),
            "per_kg_fee": str(selected_tier.per_kg_fee),
            "weight_kg": str(weight_kg),
        },
    }


def quote_cart_delivery(
    delivery_method: str,
    delivery_address: str,
    items: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Multi-farmer quote.

    Input:
      items = [{product_id, quantity}]

    Output:
      {
        total_fee,
        per_farmer: {
          farmer_id: {...quote...}
        }
      }
    """
    # -----------------------------------------------------------------------
    # Load products for grouping
    # -----------------------------------------------------------------------
    product_ids: List[UUID] = []
    for item in items:
        product_uuid = _to_uuid(item.get("product_id"))
        if product_uuid is not None:
            product_ids.append(product_uuid)

    if not product_ids:
        return {"total_fee": Decimal("0"), "per_farmer": {}}

    products = (
        db.session.execute(
            select(Product).where(Product.product_id.in_(product_ids))
        )
        .scalars()
        .all()
    )
    product_map = {str(product.product_id): product for product in products}

    # -----------------------------------------------------------------------
    # Group cart items by farmer
    # -----------------------------------------------------------------------
    grouped: Dict[str, List[Dict[str, Any]]] = {}

    for item in items:
        product_id = str(item.get("product_id"))
        product = product_map.get(product_id)
        if not product:
            continue

        farmer_id = str(getattr(product, "farmer_id", ""))
        if not farmer_id:
            continue

        grouped.setdefault(farmer_id, []).append(
            {
                "quantity": item.get("quantity") or 0,
                "pickup_only": getattr(product, "pickup_only", False),
                "weight_kg": getattr(product, "weight_kg", None),
            }
        )

    # -----------------------------------------------------------------------
    # Quote each farmer separately, then total
    # -----------------------------------------------------------------------
    per_farmer: Dict[str, Dict[str, Any]] = {}
    total = Decimal("0")

    for farmer_id_str, farmer_items in grouped.items():
        farmer_uuid = _to_uuid(farmer_id_str)
        if farmer_uuid is None:
            continue

        user = db.session.execute(
            select(User).where(User.id == farmer_uuid)
        ).scalar_one_or_none()

        farmer_location = (user.location or "") if user else ""

        quote = quote_for_farmer(
            farmer_id=farmer_uuid,
            delivery_method=delivery_method,
            delivery_address=delivery_address,
            items=farmer_items,
            farmer_location=farmer_location,
        )

        per_farmer[farmer_id_str] = quote
        total += quote["fee"]

    return {
        "total_fee": total,
        "per_farmer": per_farmer,
    }