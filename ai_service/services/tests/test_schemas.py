# =====================================================================
# ai_service/tests/test_schemas.py — Schema contract tests
# =====================================================================
# PURPOSE:
#   • Validate Pydantic schemas used by the AI service
#   • Ensure strict input validation at API boundaries
#
# DESIGN:
#   • Tests only schemas that actually exist
#   • Pydantic v2 compatible
#   • Contract-level (no business logic)
# =====================================================================

from __future__ import annotations

import pytest
from pydantic import ValidationError

# ✅ Correct import path (package-based)
from ai_service.schemas import (
    PredictionRequest,
    ForecastRequest,
    StockAlertRequest,
)


# ---------------------------------------------------------------------
# PredictionRequest
# ---------------------------------------------------------------------
def test_prediction_request_valid() -> None:
    """
    Valid PredictionRequest should pass validation.
    """
    m = PredictionRequest(crop="maize", data=[1.0, 2.0, 3.0])
    assert m.crop == "maize"
    assert len(m.data) == 3


def test_prediction_request_rejects_short_crop() -> None:
    """
    Crop name must meet minimum length.
    """
    with pytest.raises(ValidationError):
        PredictionRequest(crop="m", data=[1.0])


def test_prediction_request_rejects_empty_data() -> None:
    """
    Data series must not be empty.
    """
    with pytest.raises(ValidationError):
        PredictionRequest(crop="maize", data=[])


# ---------------------------------------------------------------------
# ForecastRequest
# ---------------------------------------------------------------------
def test_forecast_request_requires_two_points() -> None:
    """
    Forecast requires at least two historical data points.
    """
    with pytest.raises(ValidationError):
        ForecastRequest(series=[10.0], steps=3)


def test_forecast_request_valid() -> None:
    """
    Valid ForecastRequest should pass.
    """
    m = ForecastRequest(series=[10.0, 12.0, 11.5], steps=3)
    assert m.steps == 3
    assert len(m.series) == 3


# ---------------------------------------------------------------------
# StockAlertRequest
# ---------------------------------------------------------------------
def test_stock_alert_request_valid() -> None:
    """
    Valid StockAlertRequest should pass validation.
    """
    m = StockAlertRequest(
        farmer_id="farmer-123",
        threshold_days=7,
    )
    assert m.farmer_id == "farmer-123"
    assert m.threshold_days == 7


def test_stock_alert_request_rejects_invalid_days() -> None:
    """
    threshold_days must be positive.
    """
    with pytest.raises(ValidationError):
        StockAlertRequest(
            farmer_id="farmer-123",
            threshold_days=0,
        )
