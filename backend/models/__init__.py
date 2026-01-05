# ====================================================================
# backend/models/__init__.py — ORM Model Export Hub
# --------------------------------------------------------------------
# FILE ROLE:
#   Central import point so `import backend.models` loads ORM mappers.
#   This improves mapper stability and keeps CLI tooling consistent.
# ====================================================================

from __future__ import annotations

# Core tables (required)
from backend.models.user import User
from backend.models.product import Product
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.market_trend import MarketTrend

# Optional extension table
try:
    from backend.models.farmer import Farmer
except Exception:  # pragma: no cover
    Farmer = None  # type: ignore[assignment]

# Optional tables (only import if present)
try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]

try:
    from backend.models.sms_log import SmsLog
except Exception:  # pragma: no cover
    SmsLog = None  # type: ignore[assignment]

try:
    from backend.models.ai_insight import AIInsight
except Exception:  # pragma: no cover
    AIInsight = None  # type: ignore[assignment]

try:
    from backend.models.ai_stock_alert import AIStockAlert
except Exception:  # pragma: no cover
    AIStockAlert = None  # type: ignore[assignment]

# DB-backed AI governance tables (optional)
try:
    from backend.models.ai_model_accuracy_daily import AIModelAccuracyDaily
except Exception:  # pragma: no cover
    AIModelAccuracyDaily = None  # type: ignore[assignment]

try:
    from backend.models.ai_request_log import AIRequestLog
except Exception:  # pragma: no cover
    AIRequestLog = None  # type: ignore[assignment]

try:
    from backend.models.ai_prediction_log import AIPredictionLog
except Exception:  # pragma: no cover
    AIPredictionLog = None  # type: ignore[assignment]


__all__ = [
    "User",
    "Product",
    "Order",
    "OrderItem",
    "MarketTrend",
    "Farmer",
    "Rating",
    "SmsLog",
    "AIInsight",
    "AIStockAlert",
    "AIModelAccuracyDaily",
    "AIRequestLog",
    "AIPredictionLog",
]
