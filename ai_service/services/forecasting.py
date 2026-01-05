# =====================================================================
# ai_service/services/forecasting.py — Forecasting (ARIMA + fallback)
# =====================================================================
# FILE ROLE:
#   • Produces multi-step forecasts
#   • Uses ARIMA when series is long enough
#   • Falls back to deterministic trend projection for short series
# =====================================================================

from __future__ import annotations

from typing import List

import numpy as np
from statsmodels.tsa.arima.model import ARIMA


def forecast_arima(series: List[float], steps: int = 3) -> List[float]:
    arr = np.array(series, dtype=float)
    if arr.size < 2:
        raise ValueError("series must contain at least 2 values")

    # Fallback for short series
    if len(arr) < 6:
        trend = (arr[-1] - arr[-2]) if len(arr) >= 2 else 0.0
        return [float(arr[-1] + trend * i) for i in range(1, steps + 1)]

    try:
        model = ARIMA(arr, order=(1, 1, 1))
        fit = model.fit()
        fc = fit.forecast(steps=steps)
        return [float(x) for x in fc]
    except Exception:
        # Robust fallback: linear trend projection
        trend = (arr[-1] - arr[-2]) if len(arr) >= 2 else 0.0
        return [float(arr[-1] + trend * i) for i in range(1, steps + 1)]
