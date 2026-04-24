# ============================================================================
# backend/services/system_settings.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Central system settings service for AgroConnect.
#
# WHAT THIS MODULE DOES:
#   • Defines the default marketplace settings model
#   • Reads persisted settings from a JSON file in the Flask instance folder
#   • Merges stored settings over safe defaults
#   • Applies resolved settings into app.config
#   • Exposes a public-safe projection for frontend/runtime consumption
#   • Provides small helpers for reading individual settings and feature flags
#
# IMPORTANT FIXES IN THIS VERSION:
#   ✅ Fixes Pyright import issue by importing:
#        - Flask           from flask.app
#        - has_app_context from flask.ctx
#        - current_app     from flask.globals
#   ✅ Fixes current_app proxy typing issue WITHOUT calling
#      current_app._get_current_object()
#   ✅ Avoids "root_path is unknown" by reading proxy attributes through a
#      narrow Any-cast helper only where needed.
#   ✅ Keeps the same public function names for backwards compatibility.
#   ✅ Uses atomic writes and safe normalization for persisted JSON settings.
# ============================================================================

from __future__ import annotations

import copy
import json
import os
import tempfile
from typing import Any, Optional, cast

from flask.app import Flask
from flask.ctx import has_app_context
from flask.globals import current_app

# ----------------------------------------------------------------------------
# Module constants
# ----------------------------------------------------------------------------
DEFAULT_VERSION = os.environ.get("APP_VERSION", "-")
SETTINGS_FILENAME = "admin_settings.json"

KNOWN_TOP_LEVEL_SECTIONS = {
    "cache_ttl",
    "maintenance",
    "version",
    "platform",
    "marketplace",
    "checkout",
    "payments",
    "communications",
    "moderation",
    "analytics",
    "search",
}

PUBLIC_SAFE_TOP_LEVEL_SECTIONS = {
    "version",
    "maintenance",
    "platform",
    "marketplace",
    "checkout",
    "payments",
    "communications",
    "moderation",
    "analytics",
    "search",
}


# ----------------------------------------------------------------------------
# App/context helpers
# ----------------------------------------------------------------------------
def _current_app_proxy_any() -> Optional[Any]:
    """
    Return current_app through a narrow Any cast.

    WHY THIS EXISTS:
    - current_app is a Flask local proxy at runtime.
    - Some type-checking environments treat it as plain Flask, others as a
      proxy, which leads to inconsistent attribute visibility.
    - We only use this helper in a few places where proxy attribute typing
      causes false positives.
    """
    if not has_app_context():
        return None
    return cast(Any, current_app)


def _resolve_app(app: Optional[Flask] = None) -> Optional[Flask]:
    """
    Prefer an explicitly supplied Flask app.
    Otherwise, fall back to the current app proxy, cast to Flask.

    NOTE:
    We intentionally do not call _get_current_object() here because that method
    is what your type checker is currently complaining about.
    """
    if app is not None:
        return app

    proxy_app = _current_app_proxy_any()
    if proxy_app is None:
        return None

    return cast(Flask, proxy_app)


# ----------------------------------------------------------------------------
# Basic coercion helpers
# ----------------------------------------------------------------------------
def _config_source(app: Optional[Flask] = None) -> dict[str, Any]:
    """
    Return a config dictionary from either:
      • the provided Flask app
      • the current app context
      • an empty dict if neither is available
    """
    resolved_app = _resolve_app(app)
    if resolved_app is None:
        return {}
    return dict(resolved_app.config)


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """
    Robust boolean coercion.

    Important:
      bool("false") is True in Python, which is often not what we want for
      config values loaded from env vars or JSON-like sources.
    """
    if isinstance(value, bool):
        return value

    if value is None:
        return default

    if isinstance(value, (int, float)):
        return value != 0

    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False

    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default


def _ensure_dict(value: Any) -> dict[str, Any]:
    """
    Guarantee that a section is a dictionary.

    This protects against malformed JSON such as:
      "checkout": "oops"
    """
    return value if isinstance(value, dict) else {}


# ----------------------------------------------------------------------------
# Default settings model
# ----------------------------------------------------------------------------
def default_settings(app: Optional[Flask] = None) -> dict[str, Any]:
    """
    Build the default settings payload.

    These defaults are the baseline system policy. Stored JSON settings can
    override these values, and environment/app config can influence defaults.
    """
    cfg = _config_source(app)

    return {
        "cache_ttl": _coerce_int(cfg.get("CACHE_TTL", 300), 300),
        "maintenance": _coerce_bool(cfg.get("MAINTENANCE_MODE", False), False),
        "version": os.environ.get(
            "APP_VERSION",
            _coerce_str(cfg.get("APP_VERSION", DEFAULT_VERSION), DEFAULT_VERSION),
        ),
        "platform": {
            "maintenance_message": _coerce_str(
                cfg.get(
                    "MAINTENANCE_MESSAGE",
                    "Scheduled maintenance in progress. Please try again shortly.",
                ),
                "Scheduled maintenance in progress. Please try again shortly.",
            ),
            "read_only_mode": _coerce_bool(cfg.get("READ_ONLY_MODE", False), False),
            "default_report_days": _coerce_int(cfg.get("DEFAULT_REPORT_DAYS", 90), 90),
            "report_preview_rows": _coerce_int(cfg.get("REPORT_PREVIEW_ROWS", 25), 25),
        },
        "marketplace": {
            "currency_code": _coerce_str(
                cfg.get("MARKETPLACE_CURRENCY_CODE", "NAD"),
                "NAD",
            ).upper(),
            "vat_percent": _coerce_float(cfg.get("VAT_PERCENT", 15.0), 15.0),
            "low_stock_threshold": _coerce_int(cfg.get("LOW_STOCK_THRESHOLD", 5), 5),
            "featured_products_limit": _coerce_int(cfg.get("FEATURED_PRODUCTS_LIMIT", 8), 8),
            "allow_ratings": _coerce_bool(cfg.get("ALLOW_RATINGS", True), True),
            "allow_product_likes": _coerce_bool(cfg.get("ALLOW_PRODUCT_LIKES", True), True),
        },
        "checkout": {
            "allow_delivery": _coerce_bool(cfg.get("ALLOW_DELIVERY", True), True),
            "allow_pickup": _coerce_bool(cfg.get("ALLOW_PICKUP", True), True),
            "auto_cancel_unpaid_hours": _coerce_int(
                cfg.get("AUTO_CANCEL_UNPAID_HOURS", 24),
                24,
            ),
            "default_delivery_fee": _coerce_float(
                cfg.get("DEFAULT_DELIVERY_FEE", 30.0),
                30.0,
            ),
            "free_delivery_threshold": _coerce_float(
                cfg.get("FREE_DELIVERY_THRESHOLD", 500.0),
                500.0,
            ),
            "max_cart_items": _coerce_int(cfg.get("MAX_CART_ITEMS", 50), 50),
            "max_order_lines_per_checkout": _coerce_int(
                cfg.get("MAX_ORDER_LINES_PER_CHECKOUT", 20),
                20,
            ),
        },
        "payments": {
            "eft_enabled": _coerce_bool(cfg.get("EFT_ENABLED", True), True),
            "cash_on_delivery_enabled": _coerce_bool(
                cfg.get("CASH_ON_DELIVERY_ENABLED", False),
                False,
            ),
            "manual_review_enabled": _coerce_bool(cfg.get("MANUAL_REVIEW_ENABLED", True), True),
            "proof_of_payment_required_for_eft": _coerce_bool(
                cfg.get("PROOF_OF_PAYMENT_REQUIRED_FOR_EFT", True),
                True,
            ),
            "max_payment_proof_mb": _coerce_int(cfg.get("MAX_PAYMENT_PROOF_MB", 5), 5),
            "manual_review_threshold_nad": _coerce_float(
                cfg.get("MANUAL_REVIEW_THRESHOLD_NAD", 1500.0),
                1500.0,
            ),
        },
        "communications": {
            "in_app_notifications_enabled": _coerce_bool(
                cfg.get("IN_APP_NOTIFICATIONS_ENABLED", True),
                True,
            ),
            "email_notifications_enabled": _coerce_bool(
                cfg.get("EMAIL_NOTIFICATIONS_ENABLED", True),
                True,
            ),
            "sms_notifications_enabled": _coerce_bool(
                cfg.get("SMS_NOTIFICATIONS_ENABLED", True),
                True,
            ),
            "broadcast_email_enabled": _coerce_bool(
                cfg.get("BROADCAST_EMAIL_ENABLED", True),
                True,
            ),
            "broadcast_sms_enabled": _coerce_bool(
                cfg.get("BROADCAST_SMS_ENABLED", True),
                True,
            ),
        },
        "moderation": {
            "product_review_sla_hours": _coerce_int(
                cfg.get("PRODUCT_REVIEW_SLA_HOURS", 48),
                48,
            ),
            "auto_publish_approved_products": _coerce_bool(
                cfg.get("AUTO_PUBLISH_APPROVED_PRODUCTS", True),
                True,
            ),
            "require_rejection_reason": _coerce_bool(
                cfg.get("REQUIRE_REJECTION_REASON", True),
                True,
            ),
            "flag_duplicate_products": _coerce_bool(
                cfg.get("FLAG_DUPLICATE_PRODUCTS", True),
                True,
            ),
        },
        "analytics": {
            "ai_insights_enabled": _coerce_bool(cfg.get("AI_INSIGHTS_ENABLED", True), True),
            "low_stock_alerts_enabled": _coerce_bool(
                cfg.get("LOW_STOCK_ALERTS_ENABLED", True),
                True,
            ),
            "search_analytics_enabled": _coerce_bool(
                cfg.get("SEARCH_ANALYTICS_ENABLED", True),
                True,
            ),
            "market_trends_enabled": _coerce_bool(
                cfg.get("MARKET_TRENDS_ENABLED", True),
                True,
            ),
            "ranking_widgets_enabled": _coerce_bool(
                cfg.get("RANKING_WIDGETS_ENABLED", True),
                True,
            ),
        },
        "search": {
            "autocomplete_enabled": _coerce_bool(cfg.get("AUTOCOMPLETE_ENABLED", True), True),
            "trending_searches_enabled": _coerce_bool(
                cfg.get("TRENDING_SEARCHES_ENABLED", True),
                True,
            ),
            "search_history_retention_days": _coerce_int(
                cfg.get("SEARCH_HISTORY_RETENTION_DAYS", 90),
                90,
            ),
            "search_suggestions_limit": _coerce_int(
                cfg.get("SEARCH_SUGGESTIONS_LIMIT", 8),
                8,
            ),
        },
    }


# ----------------------------------------------------------------------------
# Merge / normalization helpers
# ----------------------------------------------------------------------------
def deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively merge override onto base without mutating the original inputs.
    """
    merged = copy.deepcopy(base)

    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = deep_merge(cast(dict[str, Any], merged[key]), value)
        else:
            merged[key] = value

    return merged


def normalize_settings(raw: Any, *, app: Optional[Flask] = None) -> dict[str, Any]:
    """
    Normalize any stored/raw settings payload so that:
      • it is always a dict
      • expected sections are always dict-shaped
      • defaults are always present
    """
    defaults = default_settings(app)

    if not isinstance(raw, dict):
        return defaults

    cleaned = copy.deepcopy(raw)

    for section_name in (
        "platform",
        "marketplace",
        "checkout",
        "payments",
        "communications",
        "moderation",
        "analytics",
        "search",
    ):
        cleaned[section_name] = _ensure_dict(cleaned.get(section_name))

    return deep_merge(defaults, cleaned)


# ----------------------------------------------------------------------------
# File system helpers
# ----------------------------------------------------------------------------
def _settings_path(app: Optional[Flask] = None) -> Optional[str]:
    """
    Resolve the settings file path.

    Preferred location:
      Flask instance_path/admin_settings.json

    Fallback:
      <app.root_path>/instance/admin_settings.json
    """
    target = _resolve_app(app)
    if target is None:
        return None

    # Read these via a narrow Any cast to avoid proxy/type-stub false positives.
    target_any = cast(Any, target)

    instance_dir = _coerce_str(getattr(target_any, "instance_path", None), "")
    if not instance_dir:
        root_path = _coerce_str(getattr(target_any, "root_path", None), "")
        if not root_path:
            return None
        instance_dir = os.path.join(root_path, "instance")

    os.makedirs(instance_dir, exist_ok=True)
    return os.path.join(instance_dir, SETTINGS_FILENAME)


# ----------------------------------------------------------------------------
# Read / write operations
# ----------------------------------------------------------------------------
def read_system_settings(*, app: Optional[Flask] = None) -> dict[str, Any]:
    """
    Read settings from disk and merge them over defaults.

    If the file is missing, invalid, or malformed, safe defaults are returned.
    """
    defaults = default_settings(app)
    path = _settings_path(app)

    if not path or not os.path.exists(path):
        return defaults

    try:
        with open(path, "r", encoding="utf-8") as handle:
            stored = json.load(handle)

        return normalize_settings(stored, app=app)

    except Exception:
        return defaults


def write_system_settings(settings: dict[str, Any], *, app: Optional[Flask] = None) -> None:
    """
    Persist settings to disk using an atomic write pattern.

    Why atomic write?
      Writing to a temp file and then replacing the original helps prevent
      partially-written/corrupt JSON files if the process is interrupted.
    """
    path = _settings_path(app)
    if not path:
        raise RuntimeError("Application context is required to persist system settings")

    normalized = normalize_settings(settings, app=app)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(prefix="admin_settings_", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(normalized, handle, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_path, path)

    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass


# ----------------------------------------------------------------------------
# Apply resolved settings into Flask app.config
# ----------------------------------------------------------------------------
def apply_system_settings_to_app(
    app: Flask,
    settings: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Resolve settings and project them into app.config.

    The result is also returned so callers can reuse the fully-resolved payload.
    """
    resolved = normalize_settings(
        settings if settings is not None else read_system_settings(app=app),
        app=app,
    )

    platform = _ensure_dict(resolved.get("platform"))
    marketplace = _ensure_dict(resolved.get("marketplace"))
    checkout = _ensure_dict(resolved.get("checkout"))
    payments = _ensure_dict(resolved.get("payments"))
    communications = _ensure_dict(resolved.get("communications"))
    moderation = _ensure_dict(resolved.get("moderation"))
    analytics = _ensure_dict(resolved.get("analytics"))
    search = _ensure_dict(resolved.get("search"))

    app.config["CACHE_TTL"] = _coerce_int(resolved.get("cache_ttl", 300), 300)
    app.config["MAINTENANCE_MODE"] = _coerce_bool(resolved.get("maintenance", False), False)
    app.config["APP_VERSION"] = _coerce_str(resolved.get("version"), DEFAULT_VERSION)

    app.config["MAINTENANCE_MESSAGE"] = _coerce_str(platform.get("maintenance_message"), "")
    app.config["READ_ONLY_MODE"] = _coerce_bool(platform.get("read_only_mode", False), False)
    app.config["DEFAULT_REPORT_DAYS"] = _coerce_int(platform.get("default_report_days", 90), 90)
    app.config["REPORT_PREVIEW_ROWS"] = _coerce_int(platform.get("report_preview_rows", 25), 25)

    app.config["MARKETPLACE_CURRENCY_CODE"] = _coerce_str(
        marketplace.get("currency_code", "NAD"),
        "NAD",
    ).upper()
    app.config["VAT_PERCENT"] = _coerce_float(marketplace.get("vat_percent", 15.0), 15.0)
    app.config["LOW_STOCK_THRESHOLD"] = _coerce_int(
        marketplace.get("low_stock_threshold", 5),
        5,
    )
    app.config["FEATURED_PRODUCTS_LIMIT"] = _coerce_int(
        marketplace.get("featured_products_limit", 8),
        8,
    )
    app.config["ALLOW_RATINGS"] = _coerce_bool(marketplace.get("allow_ratings", True), True)
    app.config["ALLOW_PRODUCT_LIKES"] = _coerce_bool(
        marketplace.get("allow_product_likes", True),
        True,
    )

    app.config["ALLOW_DELIVERY"] = _coerce_bool(checkout.get("allow_delivery", True), True)
    app.config["ALLOW_PICKUP"] = _coerce_bool(checkout.get("allow_pickup", True), True)
    app.config["AUTO_CANCEL_UNPAID_HOURS"] = _coerce_int(
        checkout.get("auto_cancel_unpaid_hours", 24),
        24,
    )
    app.config["DEFAULT_DELIVERY_FEE"] = _coerce_float(
        checkout.get("default_delivery_fee", 30.0),
        30.0,
    )
    app.config["FREE_DELIVERY_THRESHOLD"] = _coerce_float(
        checkout.get("free_delivery_threshold", 500.0),
        500.0,
    )
    app.config["MAX_CART_ITEMS"] = _coerce_int(checkout.get("max_cart_items", 50), 50)
    app.config["MAX_ORDER_LINES_PER_CHECKOUT"] = _coerce_int(
        checkout.get("max_order_lines_per_checkout", 20),
        20,
    )

    app.config["EFT_ENABLED"] = _coerce_bool(payments.get("eft_enabled", True), True)
    app.config["CASH_ON_DELIVERY_ENABLED"] = _coerce_bool(
        payments.get("cash_on_delivery_enabled", False),
        False,
    )
    app.config["MANUAL_REVIEW_ENABLED"] = _coerce_bool(
        payments.get("manual_review_enabled", True),
        True,
    )
    app.config["PROOF_OF_PAYMENT_REQUIRED_FOR_EFT"] = _coerce_bool(
        payments.get("proof_of_payment_required_for_eft", True),
        True,
    )
    app.config["MAX_PAYMENT_PROOF_MB"] = _coerce_int(
        payments.get("max_payment_proof_mb", 5),
        5,
    )
    app.config["MANUAL_REVIEW_THRESHOLD_NAD"] = _coerce_float(
        payments.get("manual_review_threshold_nad", 1500.0),
        1500.0,
    )

    app.config["IN_APP_NOTIFICATIONS_ENABLED"] = _coerce_bool(
        communications.get("in_app_notifications_enabled", True),
        True,
    )
    app.config["EMAIL_NOTIFICATIONS_ENABLED"] = _coerce_bool(
        communications.get("email_notifications_enabled", True),
        True,
    )
    app.config["SMS_NOTIFICATIONS_ENABLED"] = _coerce_bool(
        communications.get("sms_notifications_enabled", True),
        True,
    )
    app.config["BROADCAST_EMAIL_ENABLED"] = _coerce_bool(
        communications.get("broadcast_email_enabled", True),
        True,
    )
    app.config["BROADCAST_SMS_ENABLED"] = _coerce_bool(
        communications.get("broadcast_sms_enabled", True),
        True,
    )

    app.config["PRODUCT_REVIEW_SLA_HOURS"] = _coerce_int(
        moderation.get("product_review_sla_hours", 48),
        48,
    )
    app.config["AUTO_PUBLISH_APPROVED_PRODUCTS"] = _coerce_bool(
        moderation.get("auto_publish_approved_products", True),
        True,
    )
    app.config["REQUIRE_REJECTION_REASON"] = _coerce_bool(
        moderation.get("require_rejection_reason", True),
        True,
    )
    app.config["FLAG_DUPLICATE_PRODUCTS"] = _coerce_bool(
        moderation.get("flag_duplicate_products", True),
        True,
    )

    app.config["AI_INSIGHTS_ENABLED"] = _coerce_bool(
        analytics.get("ai_insights_enabled", True),
        True,
    )
    app.config["LOW_STOCK_ALERTS_ENABLED"] = _coerce_bool(
        analytics.get("low_stock_alerts_enabled", True),
        True,
    )
    app.config["SEARCH_ANALYTICS_ENABLED"] = _coerce_bool(
        analytics.get("search_analytics_enabled", True),
        True,
    )
    app.config["MARKET_TRENDS_ENABLED"] = _coerce_bool(
        analytics.get("market_trends_enabled", True),
        True,
    )
    app.config["RANKING_WIDGETS_ENABLED"] = _coerce_bool(
        analytics.get("ranking_widgets_enabled", True),
        True,
    )

    app.config["AUTOCOMPLETE_ENABLED"] = _coerce_bool(
        search.get("autocomplete_enabled", True),
        True,
    )
    app.config["TRENDING_SEARCHES_ENABLED"] = _coerce_bool(
        search.get("trending_searches_enabled", True),
        True,
    )
    app.config["SEARCH_HISTORY_RETENTION_DAYS"] = _coerce_int(
        search.get("search_history_retention_days", 90),
        90,
    )
    app.config["SEARCH_SUGGESTIONS_LIMIT"] = _coerce_int(
        search.get("search_suggestions_limit", 8),
        8,
    )

    return resolved


# ----------------------------------------------------------------------------
# Small public helpers
# ----------------------------------------------------------------------------
def get_system_settings() -> dict[str, Any]:
    """
    Read the fully-resolved settings using the current app context.
    """
    return read_system_settings()


def get_setting(
    path: str,
    default: Any = None,
    *,
    settings: Optional[dict[str, Any]] = None,
) -> Any:
    """
    Read a nested setting using dotted-path notation.

    Example:
      get_setting("checkout.allow_delivery", True)
      get_setting("payments.max_payment_proof_mb", 5)
    """
    payload = settings or read_system_settings()
    cursor: Any = payload

    for part in str(path or "").split("."):
        if not part:
            continue

        if not isinstance(cursor, dict) or part not in cursor:
            return default

        cursor = cursor.get(part)

    return default if cursor is None else cursor


def public_settings_projection(settings: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """
    Return only safe, frontend-consumable settings.

    This intentionally excludes implementation-only or potentially sensitive
    values that do not need to be exposed to the client.
    """
    payload = normalize_settings(settings or read_system_settings())

    platform = _ensure_dict(payload.get("platform"))
    marketplace = _ensure_dict(payload.get("marketplace"))
    checkout = _ensure_dict(payload.get("checkout"))
    payments = _ensure_dict(payload.get("payments"))
    communications = _ensure_dict(payload.get("communications"))
    moderation = _ensure_dict(payload.get("moderation"))
    analytics = _ensure_dict(payload.get("analytics"))
    search = _ensure_dict(payload.get("search"))

    return {
        "version": _coerce_str(payload.get("version"), DEFAULT_VERSION),
        "maintenance": _coerce_bool(payload.get("maintenance", False), False),
        "platform": {
            "maintenance_message": _coerce_str(platform.get("maintenance_message"), ""),
            "read_only_mode": _coerce_bool(platform.get("read_only_mode", False), False),
            "default_report_days": _coerce_int(platform.get("default_report_days", 90), 90),
            "report_preview_rows": _coerce_int(platform.get("report_preview_rows", 25), 25),
        },
        "marketplace": {
            "currency_code": _coerce_str(marketplace.get("currency_code", "NAD"), "NAD").upper(),
            "vat_percent": _coerce_float(marketplace.get("vat_percent", 15.0), 15.0),
            "low_stock_threshold": _coerce_int(marketplace.get("low_stock_threshold", 5), 5),
            "featured_products_limit": _coerce_int(
                marketplace.get("featured_products_limit", 8),
                8,
            ),
            "allow_ratings": _coerce_bool(marketplace.get("allow_ratings", True), True),
            "allow_product_likes": _coerce_bool(
                marketplace.get("allow_product_likes", True),
                True,
            ),
        },
        "checkout": {
            "allow_delivery": _coerce_bool(checkout.get("allow_delivery", True), True),
            "allow_pickup": _coerce_bool(checkout.get("allow_pickup", True), True),
            "auto_cancel_unpaid_hours": _coerce_int(
                checkout.get("auto_cancel_unpaid_hours", 24),
                24,
            ),
            "default_delivery_fee": _coerce_float(
                checkout.get("default_delivery_fee", 30.0),
                30.0,
            ),
            "free_delivery_threshold": _coerce_float(
                checkout.get("free_delivery_threshold", 500.0),
                500.0,
            ),
            "max_cart_items": _coerce_int(checkout.get("max_cart_items", 50), 50),
            "max_order_lines_per_checkout": _coerce_int(
                checkout.get("max_order_lines_per_checkout", 20),
                20,
            ),
        },
        "payments": {
            "eft_enabled": _coerce_bool(payments.get("eft_enabled", True), True),
            "cash_on_delivery_enabled": _coerce_bool(
                payments.get("cash_on_delivery_enabled", False),
                False,
            ),
            "proof_of_payment_required_for_eft": _coerce_bool(
                payments.get("proof_of_payment_required_for_eft", True),
                True,
            ),
            "max_payment_proof_mb": _coerce_int(payments.get("max_payment_proof_mb", 5), 5),
            "manual_review_enabled": _coerce_bool(
                payments.get("manual_review_enabled", True),
                True,
            ),
            "manual_review_threshold_nad": _coerce_float(
                payments.get("manual_review_threshold_nad", 1500.0),
                1500.0,
            ),
        },
        "communications": {
            "in_app_notifications_enabled": _coerce_bool(
                communications.get("in_app_notifications_enabled", True),
                True,
            ),
            "email_notifications_enabled": _coerce_bool(
                communications.get("email_notifications_enabled", True),
                True,
            ),
            "sms_notifications_enabled": _coerce_bool(
                communications.get("sms_notifications_enabled", True),
                True,
            ),
            "broadcast_email_enabled": _coerce_bool(
                communications.get("broadcast_email_enabled", True),
                True,
            ),
            "broadcast_sms_enabled": _coerce_bool(
                communications.get("broadcast_sms_enabled", True),
                True,
            ),
        },
        "moderation": {
            "product_review_sla_hours": _coerce_int(
                moderation.get("product_review_sla_hours", 48),
                48,
            ),
            "auto_publish_approved_products": _coerce_bool(
                moderation.get("auto_publish_approved_products", True),
                True,
            ),
            "require_rejection_reason": _coerce_bool(
                moderation.get("require_rejection_reason", True),
                True,
            ),
            "flag_duplicate_products": _coerce_bool(
                moderation.get("flag_duplicate_products", True),
                True,
            ),
        },
        "analytics": {
            "ai_insights_enabled": _coerce_bool(
                analytics.get("ai_insights_enabled", True),
                True,
            ),
            "low_stock_alerts_enabled": _coerce_bool(
                analytics.get("low_stock_alerts_enabled", True),
                True,
            ),
            "search_analytics_enabled": _coerce_bool(
                analytics.get("search_analytics_enabled", True),
                True,
            ),
            "market_trends_enabled": _coerce_bool(
                analytics.get("market_trends_enabled", True),
                True,
            ),
            "ranking_widgets_enabled": _coerce_bool(
                analytics.get("ranking_widgets_enabled", True),
                True,
            ),
        },
        "search": {
            "autocomplete_enabled": _coerce_bool(search.get("autocomplete_enabled", True), True),
            "trending_searches_enabled": _coerce_bool(
                search.get("trending_searches_enabled", True),
                True,
            ),
            "search_history_retention_days": _coerce_int(
                search.get("search_history_retention_days", 90),
                90,
            ),
            "search_suggestions_limit": _coerce_int(
                search.get("search_suggestions_limit", 8),
                8,
            ),
        },
    }


def is_feature_enabled(
    path: str,
    default: bool = True,
    *,
    settings: Optional[dict[str, Any]] = None,
) -> bool:
    """
    Convenience helper for feature flags and boolean policy checks.

    Example:
      if is_feature_enabled("analytics.low_stock_alerts_enabled"):
          ...
    """
    return _coerce_bool(get_setting(path, default, settings=settings), default)