# =====================================================================
# ai-service/tests/test_app_contracts.py
# PURPOSE:
#   Contract-level tests for FastAPI endpoints (no DB required).
# =====================================================================

from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "ai-service"
    assert "model_version" in data


def test_predict_basic():
    r = client.post("/v1/predict/basic", json={"crop": "maize", "data": [10, 20, 30]})
    assert r.status_code == 200
    data = r.json()
    assert data["crop"] == "maize"
    assert "prediction" in data


def test_forecast_arima_rejects_bad_series():
    r = client.post("/v1/forecast/arima", json={"series": [10], "steps": 3})
    assert r.status_code in (400, 422)  # depending on where it fails (schema vs handler)
