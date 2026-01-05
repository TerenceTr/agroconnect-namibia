# =====================================================================
# ai_service/services/__init__.py — Service Layer Public API
# =====================================================================
# FILE ROLE:
#   • Defines the official public surface of the AI service layer
#   • Prevents brittle deep imports
#   • Stable imports for:
#       - ai_service.app routes
#       - unit tests
#       - orchestration layers
#
# RULE:
#   FastAPI should import ONLY from:
#       from ai_service.services import compute_rankings, predict_price, ...
# =====================================================================

from __future__ import annotations

from ai_service.services.pricing import predict_price
from ai_service.services.demand import predict_demand
from ai_service.services.forecasting import forecast_arima
from ai_service.services.recommender import recommend_for_customer
from ai_service.services.rankings import compute_rankings
from ai_service.services.alerts import stock_alerts_for_farmer

__all__ = [
    "predict_price",
    "predict_demand",
    "forecast_arima",
    "recommend_for_customer",
    "compute_rankings",
    "stock_alerts_for_farmer",
]
