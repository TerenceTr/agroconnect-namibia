# =====================================================================
# ai_service/tests/test_schema_fuzz.py — Property-based Schema Fuzz Tests
# =====================================================================
# ROLE:
#   • Uses Hypothesis to fuzz request schemas
#   • Ensures validators reject invalid inputs reliably
#   • Prevents edge-case regressions (MSc-grade robustness)
#
# NOTE:
#   Requires: hypothesis
# =====================================================================

import pytest
from pydantic import ValidationError
from hypothesis import given, strategies as st

from ai_service.schemas import PredictionRequest, ForecastRequest, AccuracyLogRequest


@given(
    crop=st.text(min_size=0, max_size=20),
    data=st.lists(st.floats(allow_nan=False, allow_infinity=False), min_size=0, max_size=20),
)
def test_prediction_request_fuzz(crop, data):
    if len(crop) < 2 or len(data) < 1:
        with pytest.raises(ValidationError):
            PredictionRequest(crop=crop, data=data)
    else:
        m = PredictionRequest(crop=crop, data=data)
        assert m.crop == crop


@given(
    series=st.lists(st.floats(allow_nan=False, allow_infinity=False), min_size=0, max_size=10),
    steps=st.integers(min_value=-5, max_value=200),
)
def test_forecast_request_fuzz(series, steps):
    if len(series) < 2 or steps < 1 or steps > 60:
        with pytest.raises(ValidationError):
            ForecastRequest(series=series, steps=steps)
    else:
        m = ForecastRequest(series=series, steps=steps)
        assert m.steps == steps


@given(
    model_version=st.text(min_size=0, max_size=20),
    task=st.text(min_size=0, max_size=20),
    crop=st.text(min_size=0, max_size=20),
    predicted_value=st.floats(min_value=-1000, max_value=1000, allow_nan=False, allow_infinity=False),
)
def test_accuracy_log_request_fuzz(model_version, task, crop, predicted_value):
    valid_task = task in {"price", "demand", "forecast"}
    if len(model_version) < 3 or len(crop) < 2 or predicted_value < 0 or not valid_task:
        with pytest.raises(ValidationError):
            AccuracyLogRequest(
                model_version=model_version,
                task=task,
                crop=crop,
                predicted_value=predicted_value,
            )
    else:
        m = AccuracyLogRequest(
            model_version=model_version,
            task=task,
            crop=crop,
            predicted_value=predicted_value,
        )
        assert m.task == task
