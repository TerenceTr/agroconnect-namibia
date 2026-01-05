# =====================================================================
# ai_service/services/demand.py — Demand Prediction (Deterministic v1)
# =====================================================================
# FILE ROLE:
#   • Predicts near-term demand using average + trend
#   • Deterministic and interpretable baseline (MSc-friendly)
# =====================================================================

from __future__ import annotations

from typing import List

import numpy as np


def predict_demand(crop: str, series: List[float]) -> float:
    """
    Deterministic demand predictor.

    Method:
      demand = mean(series) + 1.5 * trend_per_step
    """
    arr = np.array(series, dtype=float)
    if arr.size == 0:
        return 0.0

    avg = float(np.mean(arr))
    trend = float((arr[-1] - arr[0]) / max(len(arr) - 1, 1))
    return round(avg + (trend * 1.5), 2)
