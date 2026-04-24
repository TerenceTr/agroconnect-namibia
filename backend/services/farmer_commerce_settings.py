# ============================================================================
# backend/services/farmer_commerce_settings.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   JSON-backed farmer commerce settings service.
#
# WHY THIS EXISTS:
#   • Farmer EFT / bank details already live in farmer_payment_profiles.
#   • The seller console also needs non-payment operational settings such as:
#       - sales / storefront controls
#       - fulfillment controls
#       - farmer-specific notification preferences
#       - communication preferences
#       - AI / analytics preferences
#       - business profile metadata
#   • These settings are farmer-scoped, not marketplace-global.
#
# DESIGN CHOICE:
#   We persist farmer commerce settings in per-farmer JSON files inside the
#   Flask instance folder. This keeps the implementation migration-light while
#   still giving durable backend persistence.
#
# IMPORTANT:
#   This service does NOT change customer pricing by itself. It persists the
#   settings that a later pricing / merchandising flow can apply.
#
# PYRIGHT FIXES IN THIS UPDATE:
#   ✅ Removes direct use of current_app._get_current_object(), because some
#      type stubs do not expose that attribute on _CurrentAppProxy
#   ✅ Avoids returning current_app where Pyright sees Flask | _CurrentAppProxy
#   ✅ Resolves instance_path using proxy-safe getattr(...) calls
#   ✅ Keeps runtime behavior unchanged while remaining static-type friendly
# ============================================================================

from __future__ import annotations

import json
import os
import tempfile
from copy import deepcopy
from datetime import datetime
from typing import Any, Optional, cast
from uuid import UUID

from flask import Flask, current_app


SETTINGS_DIRNAME = "farmer_settings"
SETTINGS_FILENAME_SUFFIX = "_commerce_settings.json"


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def _safe_str(v: Any, fallback: str = "") -> str:
    """Return a trimmed string fallback-safe."""
    s = str(v or "").strip()
    return s or fallback


def _safe_bool(v: Any, default: bool = False) -> bool:
    """Best-effort boolean coercion."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = _safe_str(v, "").lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _safe_int(
    v: Any,
    default: int = 0,
    minimum: Optional[int] = None,
    maximum: Optional[int] = None,
) -> int:
    """Best-effort integer coercion with optional clamping."""
    try:
        n = int(v)
    except Exception:
        n = int(default)
    if minimum is not None:
        n = max(minimum, n)
    if maximum is not None:
        n = min(maximum, n)
    return n


def _safe_float(
    v: Any,
    default: float = 0.0,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    """Best-effort float coercion with optional clamping."""
    try:
        n = float(v)
    except Exception:
        n = float(default)
    if minimum is not None:
        n = max(minimum, n)
    if maximum is not None:
        n = min(maximum, n)
    return n


def _safe_list_of_str(v: Any) -> list[str]:
    """Normalize list-like values into a unique trimmed list of strings."""
    if isinstance(v, list):
        out: list[str] = []
        seen: set[str] = set()
        for item in v:
            s = _safe_str(item)
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    if isinstance(v, str):
        parts = [p.strip() for p in v.split(",")]
        return [p for p in parts if p]

    return []


def _merge_dicts(base: dict[str, Any], raw: dict[str, Any]) -> dict[str, Any]:
    """Deep-merge nested dict structures without mutating the defaults."""
    merged = deepcopy(base)
    for key, value in (raw or {}).items():
        if isinstance(merged.get(key), dict) and isinstance(value, dict):
            merged[key] = _merge_dicts(cast(dict[str, Any], merged[key]), value)
        else:
            merged[key] = value
    return merged


# ----------------------------------------------------------------------------
# Flask path helpers
# ----------------------------------------------------------------------------
def _instance_path(app: Optional[Flask] = None) -> str:
    """
    Resolve the Flask instance_path safely.

    Why this helper exists:
      • `current_app` is a proxy at runtime.
      • Some static type stubs do not expose proxy internals like
        `_get_current_object()`.
      • Accessing the path via `getattr(..., "instance_path", "")` works both
        at runtime and keeps Pyright satisfied.
    """
    if app is not None:
        path = _safe_str(getattr(app, "instance_path", ""))
    else:
        # Treat the proxy as Any for attribute access only.
        proxy_app: Any = current_app
        path = _safe_str(getattr(proxy_app, "instance_path", ""))

    if not path:
        raise RuntimeError("Flask instance_path is not available.")

    return path


def _settings_dir(app: Optional[Flask] = None) -> str:
    """Return the on-disk folder that stores farmer JSON settings files."""
    path = os.path.join(_instance_path(app), SETTINGS_DIRNAME)
    os.makedirs(path, exist_ok=True)
    return path


def _settings_path(farmer_id: UUID | str, app: Optional[Flask] = None) -> str:
    """Return the per-farmer JSON settings file path."""
    farmer_key = _safe_str(farmer_id)
    return os.path.join(_settings_dir(app), f"{farmer_key}{SETTINGS_FILENAME_SUFFIX}")


# ----------------------------------------------------------------------------
# Default farmer commerce settings model
# ----------------------------------------------------------------------------
def default_farmer_commerce_settings() -> dict[str, Any]:
    """
    Canonical default model for seller-specific commerce settings.
    """
    return {
        "version": 1,
        "storefront": {
            "store_paused": False,
            "accept_new_orders": True,
            "show_low_stock_badge": True,
            "hide_out_of_stock_products": False,
            "featured_product_ids": [],
            "sale": {
                "enabled": False,
                "sale_name": "",
                "discount_type": "percent",  # percent | fixed
                "discount_value": 0,
                "start_at": "",
                "end_at": "",
                "apply_scope": "all",  # all | selected_products | selected_category
                "selected_product_ids": [],
                "selected_category": "",
                "banner_text": "",
                "minimum_stock_threshold": 0,
                "stack_with_other_promotions": False,
            },
        },
        "fulfillment": {
            "pickup_enabled": True,
            "delivery_enabled": True,
            "minimum_order_nad": 0,
            "preparation_lead_hours": 24,
            "same_day_cutoff_time": "12:00",
            "max_daily_orders": 0,
            "allow_substitutions": False,
            "pickup_instructions": "",
            "service_radius_km": 25,
        },
        "notifications": {
            "orders_in_app": True,
            "orders_email": False,
            "orders_sms": False,
            "messages_in_app": True,
            "messages_email": False,
            "moderation_in_app": True,
            "moderation_email": False,
            "quiet_hours_enabled": False,
            "quiet_hours_start": "21:00",
            "quiet_hours_end": "06:00",
            "urgent_override": True,
            "daily_digest_enabled": False,
            "instant_payment_proof_alerts": True,
        },
        "communication": {
            "auto_reply_enabled": False,
            "auto_reply_message": "",
            "display_response_time": True,
            "seller_welcome_message": "",
            "faq_snippets": [],
        },
        "analytics": {
            "show_market_trends": True,
            "show_stock_alerts": True,
            "show_ranking_widget": True,
            "weekly_summary_email": False,
            "custom_low_stock_threshold": 5,
            "alert_sensitivity": "medium",  # low | medium | high
            "ranking_window_days": 30,
        },
        "business_profile": {
            "store_tagline": "",
            "farm_story": "",
            "service_regions": [],
            "pickup_address": "",
            "business_phone": "",
            "public_contact_link": "",
            "operating_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat"],
            "opening_time": "08:00",
            "closing_time": "17:00",
        },
        "updated_at": None,
    }


# ----------------------------------------------------------------------------
# Normalization
# ----------------------------------------------------------------------------
def normalize_farmer_commerce_settings(raw: Any) -> dict[str, Any]:
    """
    Normalize any inbound payload into the canonical settings shape.
    """
    defaults = default_farmer_commerce_settings()
    candidate = raw if isinstance(raw, dict) else {}
    merged = _merge_dicts(defaults, candidate)

    storefront = cast(dict[str, Any], merged["storefront"])
    storefront["store_paused"] = _safe_bool(storefront.get("store_paused"), False)
    storefront["accept_new_orders"] = _safe_bool(storefront.get("accept_new_orders"), True)
    storefront["show_low_stock_badge"] = _safe_bool(storefront.get("show_low_stock_badge"), True)
    storefront["hide_out_of_stock_products"] = _safe_bool(
        storefront.get("hide_out_of_stock_products"), False
    )
    storefront["featured_product_ids"] = _safe_list_of_str(storefront.get("featured_product_ids"))

    sale = cast(dict[str, Any], storefront["sale"])
    sale["enabled"] = _safe_bool(sale.get("enabled"), False)
    sale["sale_name"] = _safe_str(sale.get("sale_name"))
    sale["discount_type"] = (
        "fixed" if _safe_str(sale.get("discount_type"), "percent").lower() == "fixed" else "percent"
    )
    sale["discount_value"] = _safe_float(sale.get("discount_value"), 0.0, minimum=0.0)
    sale["start_at"] = _safe_str(sale.get("start_at"))
    sale["end_at"] = _safe_str(sale.get("end_at"))
    sale_scope = _safe_str(sale.get("apply_scope"), "all").lower()
    sale["apply_scope"] = (
        sale_scope if sale_scope in {"all", "selected_products", "selected_category"} else "all"
    )
    sale["selected_product_ids"] = _safe_list_of_str(sale.get("selected_product_ids"))
    sale["selected_category"] = _safe_str(sale.get("selected_category"))
    sale["banner_text"] = _safe_str(sale.get("banner_text"))
    sale["minimum_stock_threshold"] = _safe_float(
        sale.get("minimum_stock_threshold"), 0.0, minimum=0.0
    )
    sale["stack_with_other_promotions"] = _safe_bool(
        sale.get("stack_with_other_promotions"), False
    )

    fulfillment = cast(dict[str, Any], merged["fulfillment"])
    fulfillment["pickup_enabled"] = _safe_bool(fulfillment.get("pickup_enabled"), True)
    fulfillment["delivery_enabled"] = _safe_bool(fulfillment.get("delivery_enabled"), True)
    fulfillment["minimum_order_nad"] = _safe_float(
        fulfillment.get("minimum_order_nad"), 0.0, minimum=0.0
    )
    fulfillment["preparation_lead_hours"] = _safe_int(
        fulfillment.get("preparation_lead_hours"), 24, minimum=0, maximum=720
    )
    fulfillment["same_day_cutoff_time"] = _safe_str(
        fulfillment.get("same_day_cutoff_time"), "12:00"
    )
    fulfillment["max_daily_orders"] = _safe_int(
        fulfillment.get("max_daily_orders"), 0, minimum=0
    )
    fulfillment["allow_substitutions"] = _safe_bool(
        fulfillment.get("allow_substitutions"), False
    )
    fulfillment["pickup_instructions"] = _safe_str(fulfillment.get("pickup_instructions"))
    fulfillment["service_radius_km"] = _safe_float(
        fulfillment.get("service_radius_km"), 25.0, minimum=0.0
    )

    notifications = cast(dict[str, Any], merged["notifications"])
    for key, default in {
        "orders_in_app": True,
        "orders_email": False,
        "orders_sms": False,
        "messages_in_app": True,
        "messages_email": False,
        "moderation_in_app": True,
        "moderation_email": False,
        "quiet_hours_enabled": False,
        "urgent_override": True,
        "daily_digest_enabled": False,
        "instant_payment_proof_alerts": True,
    }.items():
        notifications[key] = _safe_bool(notifications.get(key), default)
    notifications["quiet_hours_start"] = _safe_str(
        notifications.get("quiet_hours_start"), "21:00"
    )
    notifications["quiet_hours_end"] = _safe_str(
        notifications.get("quiet_hours_end"), "06:00"
    )

    communication = cast(dict[str, Any], merged["communication"])
    communication["auto_reply_enabled"] = _safe_bool(
        communication.get("auto_reply_enabled"), False
    )
    communication["auto_reply_message"] = _safe_str(
        communication.get("auto_reply_message")
    )
    communication["display_response_time"] = _safe_bool(
        communication.get("display_response_time"), True
    )
    communication["seller_welcome_message"] = _safe_str(
        communication.get("seller_welcome_message")
    )
    communication["faq_snippets"] = _safe_list_of_str(
        communication.get("faq_snippets")
    )

    analytics = cast(dict[str, Any], merged["analytics"])
    analytics["show_market_trends"] = _safe_bool(
        analytics.get("show_market_trends"), True
    )
    analytics["show_stock_alerts"] = _safe_bool(
        analytics.get("show_stock_alerts"), True
    )
    analytics["show_ranking_widget"] = _safe_bool(
        analytics.get("show_ranking_widget"), True
    )
    analytics["weekly_summary_email"] = _safe_bool(
        analytics.get("weekly_summary_email"), False
    )
    analytics["custom_low_stock_threshold"] = _safe_int(
        analytics.get("custom_low_stock_threshold"), 5, minimum=0, maximum=9999
    )
    sensitivity = _safe_str(analytics.get("alert_sensitivity"), "medium").lower()
    analytics["alert_sensitivity"] = (
        sensitivity if sensitivity in {"low", "medium", "high"} else "medium"
    )
    analytics["ranking_window_days"] = _safe_int(
        analytics.get("ranking_window_days"), 30, minimum=7, maximum=365
    )

    business = cast(dict[str, Any], merged["business_profile"])
    business["store_tagline"] = _safe_str(business.get("store_tagline"))
    business["farm_story"] = _safe_str(business.get("farm_story"))
    business["service_regions"] = _safe_list_of_str(business.get("service_regions"))
    business["pickup_address"] = _safe_str(business.get("pickup_address"))
    business["business_phone"] = _safe_str(business.get("business_phone"))
    business["public_contact_link"] = _safe_str(business.get("public_contact_link"))
    operating_days = _safe_list_of_str(business.get("operating_days"))
    business["operating_days"] = operating_days or cast(
        list[str], defaults["business_profile"]["operating_days"]
    )
    business["opening_time"] = _safe_str(business.get("opening_time"), "08:00")
    business["closing_time"] = _safe_str(business.get("closing_time"), "17:00")

    merged["version"] = 1
    merged["updated_at"] = _safe_str(merged.get("updated_at")) or None
    return merged


# ----------------------------------------------------------------------------
# Persistence
# ----------------------------------------------------------------------------
def read_farmer_commerce_settings(
    farmer_id: UUID | str,
    *,
    app: Optional[Flask] = None,
) -> dict[str, Any]:
    """
    Read persisted farmer settings from the instance folder.
    Returns normalized defaults if the file does not exist or cannot be read.
    """
    path = _settings_path(farmer_id, app)
    defaults = default_farmer_commerce_settings()

    if not os.path.exists(path):
        return defaults

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
        return normalize_farmer_commerce_settings(raw)
    except Exception:
        return defaults


def write_farmer_commerce_settings(
    farmer_id: UUID | str,
    settings: dict[str, Any],
    *,
    app: Optional[Flask] = None,
) -> dict[str, Any]:
    """
    Write normalized farmer settings using an atomic temp-file replace.
    """
    normalized = normalize_farmer_commerce_settings(settings)
    normalized["updated_at"] = datetime.utcnow().isoformat()

    path = _settings_path(farmer_id, app)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)

    fd, temp_path = tempfile.mkstemp(
        prefix="farmer_settings_",
        suffix=".json",
        dir=directory,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp:
            json.dump(normalized, tmp, indent=2, ensure_ascii=False)

        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass

    return normalized