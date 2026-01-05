# =====================================================================
# ai_service/services/pricing.py — Price Prediction (Deterministic v1)
# =====================================================================
# FILE ROLE:
#   • Stable, explainable baseline price estimator
#   • Deterministic behavior supports reproducibility
# =====================================================================

from __future__ import annotations

from typing import List

import numpy as np


CROP_MULTIPLIER = {
    "maize": 1.12,
    "wheat": 1.18,
    "tomato": 0.94,
    "onion": 1.04,
    "mahangu": 1.10,  # Namibia-relevant
    "sorghum": 1.08,
}


def predict_price(crop: str, features: List[float]) -> float:
    """
    Deterministic baseline price model:
      price = mean(features) * crop_multiplier
    """
    arr = np.array(features, dtype=float)
    if arr.size == 0:
        return 0.0

    base = float(np.mean(arr))
    factor = CROP_MULTIPLIER.get(crop.lower().strip(), 1.00)
    return round(base * factor, 2)
