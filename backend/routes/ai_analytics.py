# ============================================================================
# backend/routes/ai_analytics.py — AI Gateway + Admin AI Analytics
# ============================================================================
# FILE ROLE:
#   • AI gateway endpoints used by dashboards
#   • Admin AI analytics endpoints used by frontend widgets:
#       GET /api/ai/analytics/model-accuracy
#       GET /api/ai/analytics/sales-by-category
#
# PYRIGHT FIX:
#   Import from Flask submodules for cleaner typing.
# ============================================================================

from __future__ import annotations

from typing import Any

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify

from backend.security import admin_required, token_required
from backend.services.ai_engine import (
    average_purchases_by_location,
    forecast_product_demand,
    rank_farmers_by_rating,
    recommend_market_price,
)
from backend.services.analytics_service import get_ranking_inputs, get_stock_alert_inputs
from backend.services.ai_analytics_service import get_model_accuracy_series, get_sales_by_category

ai_bp = Blueprint("ai", __name__)


@ai_bp.route("/ping", methods=["GET"])
def ping() -> Any:
    return jsonify({"status": "ok", "service": "ai-gateway"})


# --------------------------------------------------------------------
# AI / dashboard support endpoints
# --------------------------------------------------------------------
@ai_bp.route("/forecast-demand", methods=["GET"])
@token_required
def forecast_demand() -> Any:
    months = int(request.args.get("months", 6))
    return jsonify(forecast_product_demand(months))


@ai_bp.route("/recommend-price", methods=["GET"])
@token_required
def recommend_price() -> Any:
    product_id = request.args.get("product_id", "")
    return jsonify(recommend_market_price(product_id))


@ai_bp.route("/rank-farmers", methods=["GET"])
@token_required
def farmer_ranking() -> Any:
    return jsonify(rank_farmers_by_rating())


@ai_bp.route("/average-purchases-location", methods=["GET"])
@token_required
def location_stats() -> Any:
    return jsonify(average_purchases_by_location())


@ai_bp.route("/ranking-inputs", methods=["GET"])
@token_required
def ranking_inputs() -> Any:
    window_days = int(request.args.get("window_days", 30))
    top_n = int(request.args.get("top_n", 10))
    return jsonify(get_ranking_inputs(window_days, top_n))


@ai_bp.route("/stock-alert-inputs", methods=["GET"])
@token_required
def stock_alert_inputs() -> Any:
    farmer_id = request.args.get("farmer_id")
    days = int(request.args.get("days", 7))
    return jsonify(get_stock_alert_inputs(farmer_id, days))


# --------------------------------------------------------------------
# Admin AI analytics endpoints (used by frontend widgets)
# --------------------------------------------------------------------
@ai_bp.route("/analytics/model-accuracy", methods=["GET"])
@token_required
@admin_required
def model_accuracy() -> Any:
    """
    Returns chart-ready series:
      { labels:[], accuracy:[], confidence:[] }
    """
    days = int(request.args.get("days", 30))
    task = request.args.get("task") or None
    crop = request.args.get("crop") or None
    model_version = request.args.get("model_version") or None

    return jsonify(get_model_accuracy_series(days=days, task=task, crop=crop, model_version=model_version))


@ai_bp.route("/analytics/sales-by-category", methods=["GET"])
@token_required
@admin_required
def sales_by_category() -> Any:
    """
    Returns:
      { labels:[], values:[], confidence:[] }
    """
    days = int(request.args.get("days", 30))
    return jsonify(get_sales_by_category(days=days))
