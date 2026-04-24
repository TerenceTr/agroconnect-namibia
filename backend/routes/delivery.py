# ============================================================================
# backend/routes/delivery.py — Delivery Quote API
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Provides delivery quote endpoint (backend-only logic).
#
# ENDPOINT:
#   POST /api/delivery/quote
#     body: { delivery_method, delivery_address, items:[{product_id, quantity}] }
#
# THIS VERSION FIXES:
#   ✅ Pyright import issues for Blueprint / request / jsonify
#   ✅ Stronger request payload normalization
#   ✅ Ensures quote_cart_delivery receives real `str` values
#   ✅ Uses typed JSON response helper instead of tuple-style returns
# ============================================================================

from __future__ import annotations

from typing import Any, Dict, List

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Response

from backend.services.delivery_quote import quote_cart_delivery
from backend.utils.require_auth import require_auth

delivery_bp = Blueprint("delivery", __name__, url_prefix="/api/delivery")


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _json(payload: Dict[str, Any], status: int = 200) -> Response:
    """
    Return a real Flask Response with an explicit status code.
    """
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _safe_str(value: Any, default: str = "") -> str:
    """
    Best-effort string coercion that always returns a real str.
    """
    if value is None:
        return default
    try:
        text_value = str(value).strip()
    except Exception:
        return default
    return text_value or default


# ----------------------------------------------------------------------------
# Route
# ----------------------------------------------------------------------------
@delivery_bp.post("/quote")
@require_auth()
def delivery_quote() -> Response:
    """
    Quote delivery fees for a cart grouped by farmer/service logic.

    Expected JSON body:
      {
        "delivery_method": "pickup" | "delivery",
        "delivery_address": "Windhoek, Namibia",
        "items": [{"product_id": "...", "quantity": 2}, ...]
      }
    """
    raw_payload = request.get_json(silent=True) or {}
    payload: Dict[str, Any] = raw_payload if isinstance(raw_payload, dict) else {}

    # Normalize text inputs into guaranteed strings for the service layer.
    delivery_method = _safe_str(payload.get("delivery_method"), "pickup").lower()
    delivery_address = _safe_str(payload.get("delivery_address"), "")

    # Keep method constrained to expected values.
    if delivery_method not in {"pickup", "delivery"}:
        delivery_method = "pickup"

    raw_items = payload.get("items")
    items: List[Dict[str, Any]] = raw_items if isinstance(raw_items, list) else []

    if not items:
        return _json({"success": False, "message": "items[] required"}, 400)

    # Service expects concrete str inputs; the normalization above guarantees that.
    result = quote_cart_delivery(
        delivery_method=delivery_method,
        delivery_address=delivery_address,
        items=items,
    )

    per_farmer_out: Dict[str, Any] = {}
    raw_per_farmer = result.get("per_farmer", {}) or {}

    if isinstance(raw_per_farmer, dict):
        for farmer_id, quote in raw_per_farmer.items():
            if not isinstance(quote, dict):
                continue

            per_farmer_out[str(farmer_id)] = {
                **quote,
                "fee": str(quote.get("fee", 0)),
            }

    return _json(
        {
            "success": True,
            "delivery_method": delivery_method,
            "delivery_address": delivery_address,
            "total_fee": str(result.get("total_fee", 0)),
            "per_farmer": per_farmer_out,
        }
    )