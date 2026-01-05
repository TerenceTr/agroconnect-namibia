# =====================================================================
# ai_service/services/alerts.py — Stock Level Alerts
# =====================================================================
# FILE ROLE:
#   • Predicts near-term demand per product
#   • Flags inventory shortages
#   • Produces deterministic, explainable restock recommendations
#
# DATA FLOW:
#   1) Backend supplies inventory + sales time series
#   2) AI predicts demand (predict_demand)
#   3) Service computes recommended restock + severity band
#
# DESIGN:
#   • Pure service layer (NO FastAPI imports)
#   • Backend boundary: ai_service.services._backend
# =====================================================================

from __future__ import annotations

from typing import Any, Dict, List

from ai_service.services._backend import backend_get
from ai_service.services.base import retry, service_logger, timed
from ai_service.services.demand import predict_demand


@retry(attempts=3, delay_seconds=0.5)
@timed("alerts.fetch_stock_inputs")
async def _fetch_stock_inputs(farmer_id: str, threshold_days: int) -> Dict[str, Any]:
    """Fetch inventory + sales time-series inputs from backend."""
    return await backend_get(
        "/api/ai/internal/stock-inputs",
        params={"farmer_id": farmer_id, "days": threshold_days},
        breaker_name="stock_alerts",
    )


@timed("alerts.stock_alerts_for_farmer")
async def stock_alerts_for_farmer(farmer_id: str, threshold_days: int) -> List[Dict[str, Any]]:
    """Compute stock shortage alerts for a single farmer."""
    service_logger.info("stock_alerts_for_farmer(farmer_id=%s, days=%d)", farmer_id, threshold_days)

    payload = await _fetch_stock_inputs(farmer_id, threshold_days)
    items = payload.get("items", [])

    if not isinstance(items, list) or not items:
        return []

    alerts: List[Dict[str, Any]] = []

    for it in items:
        series = it.get("recent_sales_series") or []
        crop = str(it.get("product_name") or it.get("crop") or "unknown")

        # Ensure we always have at least two points for trend calc
        xs = [float(x) for x in series] if isinstance(series, list) and series else [0.0, 0.0]

        predicted = float(predict_demand(crop, xs))
        stock = float(it.get("available_stock") or 0.0)

        recommended = max(predicted - stock, 0.0)
        if recommended <= 0:
            continue

        # Severity heuristic (explainable):
        #   high if shortage is >25% of predicted demand (or >1 unit)
        severity = "medium"
        if recommended > max(predicted * 0.25, 1.0):
            severity = "high"

        alerts.append(
            {
                "product_id": str(it.get("product_id", "")),
                "product_name": crop,
                "predicted_demand": round(predicted, 2),
                "available_stock": round(stock, 2),
                "recommended_restock": round(recommended, 2),
                "severity": severity,
            }
        )

    # High severity first, then biggest shortage
    alerts.sort(key=lambda a: (0 if a["severity"] == "high" else 1, -float(a["recommended_restock"])))
    return alerts
