# ============================================================================
# backend/models/__init__.py — ORM Import Hub (STRICT REVIEW MODEL REGISTRATION)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Central import hub so SQLAlchemy relationship("...") targets are registered
#   before configure_mappers() runs in backend/app.py.
#
# IMPORTANT FIX IN THIS VERSION:
#   ✅ Review workflow models are imported STRICTLY, not swallowed silently
#   ✅ If one of those models has a real import error, Flask will now show the
#      true root cause instead of only "name 'RatingResponse' is not defined"
#   ✅ Ensures these classes are present in the ORM registry:
#        - Rating
#        - RatingResponse
#        - RatingFlag
#        - ReviewPolicyAction
#        - ComplaintTaxonomy
#        - ReviewIssueLink
# ============================================================================

from __future__ import annotations

import importlib
import importlib.util
from typing import Any, Optional


def _module_exists(module_path: str) -> bool:
    try:
        return importlib.util.find_spec(module_path) is not None
    except Exception:
        return False


def _import_symbol(module_path: str, symbol: str) -> Any:
    module = importlib.import_module(module_path)
    return getattr(module, symbol)


def _maybe(module_path: str, symbol: str) -> Optional[Any]:
    if not _module_exists(module_path):
        return None
    try:
        return _import_symbol(module_path, symbol)
    except Exception:
        return None


def _maybe_any(module_path: str, *symbols: str) -> Optional[Any]:
    if not _module_exists(module_path):
        return None

    for symbol in symbols:
        try:
            return _import_symbol(module_path, symbol)
        except Exception:
            continue
    return None


# ----------------------------------------------------------------------------
# Core models (must exist)
# ----------------------------------------------------------------------------
User = _import_symbol("backend.models.user", "User")
Product = _import_symbol("backend.models.product", "Product")
Order = _import_symbol("backend.models.order", "Order")

# ----------------------------------------------------------------------------
# Common business models
# ----------------------------------------------------------------------------
Farmer = _maybe("backend.models.farmer", "Farmer")
OrderItem = _maybe("backend.models.order_item", "OrderItem")
CartItem = _maybe("backend.models.cart_item", "CartItem")
RefreshToken = _maybe("backend.models.refresh_token", "RefreshToken")
MarketTrend = _maybe("backend.models.market_trend", "MarketTrend")
Payment = _maybe("backend.models.payment", "Payment")
Inventory = _maybe("backend.models.inventory", "Inventory")
SmsLog = _maybe("backend.models.sms_log", "SmsLog")

# ----------------------------------------------------------------------------
# REVIEW / GOVERNANCE MODELS
# IMPORTANT:
# These are imported STRICTLY so SQLAlchemy can resolve relationship targets.
# Do not wrap these in _maybe(), otherwise mapper errors get hidden and later
# show up only as unresolved class names.
# ----------------------------------------------------------------------------
Rating = _import_symbol("backend.models.rating", "Rating")
RatingResponse = _import_symbol("backend.models.rating_response", "RatingResponse")
RatingFlag = _import_symbol("backend.models.rating_flag", "RatingFlag")
ReviewPolicyAction = _import_symbol("backend.models.review_policy_action", "ReviewPolicyAction")
ComplaintTaxonomy = _import_symbol("backend.models.complaint_taxonomy", "ComplaintTaxonomy")
ReviewIssueLink = _import_symbol("backend.models.review_issue_link", "ReviewIssueLink")

# ----------------------------------------------------------------------------
# AI / analytics models
# ----------------------------------------------------------------------------
AIInsight = _maybe("backend.models.ai_insight", "AIInsight")
AIStockAlert = _maybe("backend.models.ai_stock_alert", "AIStockAlert")
AIGovernanceLog = _maybe("backend.models.ai_governance_log", "AIGovernanceLog")
AIModelMetric = _maybe("backend.models.ai_model_metric", "AIModelMetric")
AIModelRun = _maybe("backend.models.ai_model_run", "AIModelRun")
AIModelAccuracyDaily = _maybe("backend.models.ai_model_accuracy_daily", "AIModelAccuracyDaily")
AIPredictionLog = _maybe("backend.models.ai_prediction_log", "AIPredictionLog")
AIRequestLog = _maybe("backend.models.ai_request_log", "AIRequestLog")

# ----------------------------------------------------------------------------
# Customer / farmer support models
# ----------------------------------------------------------------------------
ProductLike = _maybe("backend.models.product_like", "ProductLike")
FarmerPaymentProfile = _maybe("backend.models.farmer_payment_profile", "FarmerPaymentProfile")
Notification = _maybe("backend.models.notification", "Notification")
MessageThread = _maybe("backend.models.message_thread", "MessageThread")
MessageEntry = _maybe("backend.models.message_entry", "MessageEntry")

# ----------------------------------------------------------------------------
# Admin / audit / SLA models
# ----------------------------------------------------------------------------
AdminAuditLog = _maybe("backend.models.admin_audit_event", "AdminAuditLog")
AdminSLADailySnapshot = _maybe("backend.models.admin_sla_snapshot", "AdminSLADailySnapshot")

SLADailySnapshot = _maybe_any(
    "backend.models.sla_daily_snapshot",
    "SLADailySnapshot",
    "SlaDailySnapshot",
)

LoginEvent = _maybe("backend.models.login_event", "LoginEvent")
UserActivityEvent = _maybe("backend.models.user_activity_event", "UserActivityEvent")

# ----------------------------------------------------------------------------
# Delivery / moderation support
# ----------------------------------------------------------------------------
DeliveryTier = _maybe("backend.models.delivery_tier", "DeliveryTier")
FarmerDeliveryTier = _maybe("backend.models.farmer_delivery_tier", "FarmerDeliveryTier")
ProductModerationEvent = _maybe(
    "backend.models.product_moderation_event",
    "ProductModerationEvent",
)

__all__ = (
    "User",
    "Product",
    "Order",
    "Farmer",
    "OrderItem",
    "CartItem",
    "RefreshToken",
    "MarketTrend",
    "Payment",
    "Inventory",
    "SmsLog",
    "Rating",
    "RatingResponse",
    "RatingFlag",
    "ReviewPolicyAction",
    "ComplaintTaxonomy",
    "ReviewIssueLink",
    "AIInsight",
    "AIStockAlert",
    "AIGovernanceLog",
    "AIModelMetric",
    "AIModelRun",
    "AIModelAccuracyDaily",
    "AIPredictionLog",
    "AIRequestLog",
    "ProductLike",
    "FarmerPaymentProfile",
    "Notification",
    "MessageThread",
    "MessageEntry",
    "AdminAuditLog",
    "AdminSLADailySnapshot",
    "SLADailySnapshot",
    "LoginEvent",
    "UserActivityEvent",
    "DeliveryTier",
    "FarmerDeliveryTier",
    "ProductModerationEvent",
)