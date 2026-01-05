# ====================================================================
# backend/services/stock_alert_service.py — AI Stock Alert Persistence
# ====================================================================
# FILE ROLE:
#   • Persist AI-generated stock alerts (write-back from ai-service)
#   • Provide farmer dashboard read endpoints
#   • Optionally trigger SMS for high severity alerts
#
# IMPORTANT:
#   • Backend is the ONLY component that writes DB.
#   • ai-service sends predictions only (no DB access).
# ====================================================================

from __future__ import annotations

from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import desc

from backend.database.db import db
from backend.models.ai_stock_alert import AIStockAlert
from backend.services.sms_service import send_sms


def _to_uuid(value: Any) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except Exception:
        return None


def upsert_stock_alerts(*, farmer_id: str, alerts: List[Dict[str, Any]], model_version: str) -> int:
    """
    Persist AI-generated stock alerts.
    Returns number of alerts saved.

    NOTE:
      This implementation inserts new rows.
      If you want true "upsert", you’ll need a unique constraint
      (e.g., farmer_id + product_id + computed_date) + ON CONFLICT handling.
    """
    farmer_uuid = _to_uuid(farmer_id)
    if farmer_uuid is None:
        return 0

    saved = 0

    for a in alerts:
        product_uuid = _to_uuid(a.get("product_id"))
        if product_uuid is None:
            continue

        # SQLAlchemy-safe creation (no constructor kwargs)
        alert = AIStockAlert()
        alert.farmer_id = farmer_uuid
        alert.product_id = product_uuid
        alert.predicted_demand = float(a.get("predicted_demand") or 0.0)
        alert.available_stock = float(a.get("available_stock") or 0.0)
        alert.recommended_restock = float(a.get("recommended_restock") or 0.0)
        alert.severity = str(a.get("severity") or "low")
        alert.model_version = str(model_version or "unknown")

        db.session.add(alert)
        saved += 1

        # Optional: HIGH severity SMS
        if (a.get("severity") == "high") and a.get("farmer_phone"):
            send_sms(
                to=str(a["farmer_phone"]),
                body=(
                    "⚠️ HIGH STOCK ALERT\n"
                    f"Product: {a.get('product_name', 'Unknown')}\n"
                    "Demand exceeds available stock.\n"
                    f"Recommended restock: {alert.recommended_restock}"
                ),
            )

    db.session.commit()
    return saved


def get_stock_alerts_for_farmer(farmer_id: str) -> List[Dict[str, Any]]:
    """
    Retrieve persisted stock alerts for a farmer (latest first).
    """
    farmer_uuid = _to_uuid(farmer_id)
    if farmer_uuid is None:
        return []

    rows = (
        db.session.query(AIStockAlert)  # type: ignore[attr-defined]
        .filter(AIStockAlert.farmer_id == farmer_uuid)
        .order_by(desc(AIStockAlert.computed_at))
        .all()
    )

    return [
        {
            "alert_id": str(a.alert_id),
            "product_id": str(a.product_id),
            "predicted_demand": float(a.predicted_demand),
            "available_stock": float(a.available_stock),
            "recommended_restock": float(a.recommended_restock),
            "severity": str(a.severity),
            "model_version": str(a.model_version),
            "computed_at": a.computed_at.isoformat(),
        }
        for a in rows
    ]
