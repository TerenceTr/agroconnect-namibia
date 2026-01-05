# =====================================================================
# ai_service/services/distance.py — Distance Utilities (Haversine)
# =====================================================================
# FILE ROLE:
#   • Provides distance calculation for geo-aware recommendations
#   • Used by recommender scoring
# =====================================================================

from __future__ import annotations

import math
from typing import Optional


def haversine_km(
    lat1: Optional[float],
    lng1: Optional[float],
    lat2: Optional[float],
    lng2: Optional[float],
) -> Optional[float]:
    if lat1 is None or lng1 is None or lat2 is None or lng2 is None:
        return None

    r = 6371.0
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlambda = math.radians(lng2 - lng1)

    a = (math.sin(dphi / 2) ** 2) + math.cos(phi1) * math.cos(phi2) * (math.sin(dlambda / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return float(r * c)
