# =====================================================================
# ai_service/tests/test_openapi_contract.py
# =====================================================================
# PURPOSE:
#   • Detects breaking API contract changes
#   • Ensures OpenAPI remains stable across refactors
# =====================================================================

from ai_service.app import app


def test_openapi_snapshot():
    schema = app.openapi()

    # Critical endpoints must exist
    paths = schema["paths"]

    assert "/v1/predict/basic" in paths
    assert "/v1/rankings" in paths
    assert "/v1/alerts/stock" in paths

    # Critical schemas must exist
    components = schema["components"]["schemas"]

    assert "PredictionRequest" in components
    assert "StockAlertItem" in components
    assert "AccuracyLogRequest" in components
