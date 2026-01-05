# ====================================================================
# backend/services/__init__.py — Central Service Registry
# ====================================================================
# FILE ROLE:
#   • Provides a stable import surface for the backend service layer.
#   • Routes should import ONLY from backend.services to reduce churn.
#   • Helps prevent circular imports by centralizing exports.
#
# DESIGN RULES:
#   • Services may import other services carefully (avoid cycles).
#   • Routes are thin; business logic and DB reads live in services.
# ====================================================================

from __future__ import annotations

# --------------------------------------------------------------------
# Domain services (business logic + orchestration)
# --------------------------------------------------------------------
from . import product_service
from . import analytics_service
from . import stock_alert_service

# --------------------------------------------------------------------
# Internal analytics engine (pure read-only SQLAlchemy queries)
# --------------------------------------------------------------------
from .ai_engine import (
    forecast_product_demand,
    recommend_market_price,
    rank_farmers_by_rating,
    average_purchases_by_location,
)

# --------------------------------------------------------------------
# Email services (sync + queue worker)
# --------------------------------------------------------------------
from .mailer import send_email, send_email_template
from .email_queue import enqueue_email, start_email_worker

# --------------------------------------------------------------------
# SMS services (sync + queue worker)
# --------------------------------------------------------------------
from .sms_service import send_sms, send_sms_template
from .sms_templates import render_sms_template
from .sms_queue import enqueue_sms, start_sms_worker

__all__ = [
    # Modules
    "product_service",
    "analytics_service",
    "stock_alert_service",
    # Analytics engine
    "forecast_product_demand",
    "recommend_market_price",
    "rank_farmers_by_rating",
    "average_purchases_by_location",
    # Email
    "send_email",
    "send_email_template",
    "enqueue_email",
    "start_email_worker",
    # SMS
    "send_sms",
    "send_sms_template",
    "render_sms_template",
    "enqueue_sms",
    "start_sms_worker",
]
