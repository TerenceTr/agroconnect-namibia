# ============================================================================
# backend/services/delivery_pricing.py — Delivery Quote Suggestion (Distance-Based)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Provide a practical delivery fee suggestion using:
#   • Text match for towns in farmer.location + delivery_address
#   • Haversine distance between known Namibian towns (approx centroids)
#   • Fee formula: base_fee + per_km * distance, clamped
# ============================================================================

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP
from typing import Optional

TOWNS = {
    "windhoek": (-22.5609, 17.0658),
    "oshakati": (-17.7886, 15.7044),
    "ongwediva": (-17.7833, 15.7667),
    "rundu": (-17.9333, 19.7667),
    "katima mulilo": (-17.5000, 24.2667),
    "swakopmund": (-22.6784, 14.5266),
    "walvis bay": (-22.9576, 14.5053),
    "keetmanshoop": (-26.5833, 18.1333),
    "mariental": (-24.6167, 17.9667),
    "otjiwarongo": (-20.4637, 16.6477),
    "grootfontein": (-19.5667, 18.1167),
    "tsumeb": (-19.2333, 17.7167),
    "eenhana": (-17.4667, 16.3333),
    "okahandja": (-21.9833, 16.9167),
}

_WORD_RE = re.compile(r"[a-zA-Z]+")


@dataclass(frozen=True)
class DeliveryQuote:
    distance_km: Decimal
    suggested_fee: Decimal
    from_town: str
    to_town: str


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1 = math.radians(lat1)
    p2 = math.radians(lat2)
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)

    a = math.sin(dlat / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlon / 2) ** 2
    c = 2 * math.asin(math.sqrt(a))
    return r * c


def _find_town(text: str) -> Optional[str]:
    t = (text or "").strip().lower()
    if not t:
        return None

    for town in sorted(TOWNS.keys(), key=len, reverse=True):
        if town in t:
            return town

    words = {w.lower() for w in _WORD_RE.findall(t)}
    for town in TOWNS.keys():
        if town in words:
            return town

    return None


def suggest_delivery_quote(
    *,
    farmer_location: str,
    delivery_address: str,
    base_fee: Decimal,
    per_km_fee: Decimal,
    min_fee: Decimal,
    max_fee: Decimal,
) -> Optional[DeliveryQuote]:
    from_town = _find_town(farmer_location)
    to_town = _find_town(delivery_address)

    if not from_town or not to_town:
        return None

    lat1, lon1 = TOWNS[from_town]
    lat2, lon2 = TOWNS[to_town]

    km = Decimal(str(_haversine_km(lat1, lon1, lat2, lon2))).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

    fee = (base_fee + per_km_fee * km).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    if fee < min_fee:
        fee = min_fee
    if fee > max_fee:
        fee = max_fee

    return DeliveryQuote(distance_km=km, suggested_fee=fee, from_town=from_town, to_town=to_town)
