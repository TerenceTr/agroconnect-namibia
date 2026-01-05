# =====================================================================
# ai_service/tests/test_response_schemas.py
# =====================================================================

import pytest
from pydantic import ValidationError

from ai_service.schemas import StockAlertItem, RankingItem


def test_stock_alert_item_valid():
    m = StockAlertItem(
        product_id="p1",
        product_name="Maize",
        predicted_demand=10,
        available_stock=3,
        recommended_restock=7,
        severity="high",
    )
    assert m.severity == "high"


def test_stock_alert_item_invalid_severity():
    with pytest.raises(ValidationError):
        StockAlertItem(
            product_id="p1",
            product_name="Maize",
            predicted_demand=10,
            available_stock=3,
            recommended_restock=7,
            severity="critical",
        )


def test_ranking_item_valid():
    r = RankingItem(entity_id="x", name="Test", score=1.23)
    assert r.score == 1.23
