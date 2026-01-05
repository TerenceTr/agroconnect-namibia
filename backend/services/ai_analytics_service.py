# ====================================================================
# backend/services/ai_analytics_service.py — Admin AI Analytics Queries (Multi-item)
# ====================================================================
# ✅ FILE ROLE:
#   Dashboard-ready analytics for AI governance views:
#     • Model accuracy series (ai_model_accuracy_daily; fallback prediction logs)
#     • Sales by category (revenue)
#
# ✅ WHY THIS FILE WAS UPDATED:
#   Multi-item schema:
#     Revenue is stored per line item (order_items.line_total)
#   NOT per order row tied to a single product.
# ====================================================================

from __future__ import annotations

from datetime import date, datetime, timedelta
from math import log10
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import Date, cast, desc, func

from backend.database.db import db
from backend.models.ai_model_accuracy_daily import AIModelAccuracyDaily
from backend.models.ai_prediction_log import AIPredictionLog
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product


def clamp01(x: Any) -> float:
    try:
        v = float(x)
    except Exception:
        return 0.0
    return 0.0 if v < 0.0 else 1.0 if v > 1.0 else v


def _mape_to_percent(mape: float) -> float:
    """
    MAPE may be stored as:
      • 0..1   fraction
      • 0..100 percent
    Normalize to percent.
    """
    m = float(mape or 0.0)
    return (m * 100.0) if m <= 1.5 else m


def _confidence(n: int, accuracy_pct: float) -> float:
    """Explainable confidence heuristic."""
    n = max(int(n), 0)
    acc = max(0.0, min(float(accuracy_pct), 100.0))
    size_factor = min(1.0, 0.25 + (log10(n + 1) / 2.0))  # 0.25..1.0
    acc_factor = acc / 100.0
    return clamp01(size_factor * acc_factor)


def get_model_accuracy_series(
    days: int = 30,
    task: Optional[str] = None,
    crop: Optional[str] = None,
    model_version: Optional[str] = None,
) -> Dict[str, List[Any]]:
    """
    Returns:
      { labels:[YYYY-MM-DD...], accuracy:[0..100...], confidence:[0..1...] }

    Primary source:
      ai_model_accuracy_daily

    Fallback:
      ai_prediction_logs (derives MAPE-like signal where actual_value exists)
    """
    days = max(int(days), 1)
    since_day = date.today() - timedelta(days=days - 1)

    # ------------------------------------------------------------
    # 1) Daily accuracy table
    # ------------------------------------------------------------
    q = (
        db.session.query(  # type: ignore[attr-defined]
            AIModelAccuracyDaily.day.label("day"),
            func.avg(AIModelAccuracyDaily.mape).label("mape"),
            func.sum(AIModelAccuracyDaily.n).label("n"),
        )
        .filter(AIModelAccuracyDaily.day >= since_day)
    )

    if task:
        q = q.filter(AIModelAccuracyDaily.task == task)
    if crop:
        q = q.filter(AIModelAccuracyDaily.crop == crop)
    if model_version:
        q = q.filter(AIModelAccuracyDaily.model_version == model_version)

    rows: List[Tuple[date, float, int]] = (
        q.group_by(AIModelAccuracyDaily.day)
        .order_by(AIModelAccuracyDaily.day)
        .all()
    )

    if rows:
        labels: List[str] = []
        accuracy: List[float] = []
        confidence: List[float] = []

        for d, mape, n in rows:
            mape_pct = _mape_to_percent(float(mape or 0.0))
            acc_pct = max(0.0, min(100.0, 100.0 - mape_pct))
            labels.append(d.isoformat())
            accuracy.append(round(acc_pct, 2))
            confidence.append(round(_confidence(int(n or 0), acc_pct), 3))

        return {"labels": labels, "accuracy": accuracy, "confidence": confidence}

    # ------------------------------------------------------------
    # 2) Fallback: derive from prediction logs
    # ------------------------------------------------------------
    since_dt = datetime.utcnow() - timedelta(days=days)
    day_expr = cast(AIPredictionLog.predicted_at, Date)

    pred_minus_actual = (AIPredictionLog.predicted_value - AIPredictionLog.actual_value)

    q2 = (
        db.session.query(  # type: ignore[attr-defined]
            day_expr.label("day"),
            func.count(AIPredictionLog.log_id).label("n"),
            func.avg(func.abs(pred_minus_actual) / func.nullif(func.abs(AIPredictionLog.actual_value), 0.0)).label(
                "mape_frac"
            ),
        )
        .filter(AIPredictionLog.predicted_at >= since_dt)
        .filter(AIPredictionLog.actual_value.isnot(None))
    )

    if task:
        q2 = q2.filter(AIPredictionLog.task == task)
    if crop:
        q2 = q2.filter(AIPredictionLog.crop == crop)
    if model_version:
        q2 = q2.filter(AIPredictionLog.model_version == model_version)

    rows2 = q2.group_by(day_expr).order_by(day_expr).all()

    labels2: List[str] = []
    accuracy2: List[float] = []
    confidence2: List[float] = []

    for d, n, mape_frac in rows2:
        mape_pct = float(mape_frac or 0.0) * 100.0
        acc_pct = max(0.0, min(100.0, 100.0 - mape_pct))
        labels2.append(d.isoformat() if hasattr(d, "isoformat") else str(d))
        accuracy2.append(round(acc_pct, 2))
        confidence2.append(round(_confidence(int(n or 0), acc_pct), 3))

    return {"labels": labels2, "accuracy": accuracy2, "confidence": confidence2}


def get_sales_by_category(days: int = 30) -> Dict[str, List[Any]]:
    """
    Returns:
      { labels:[category...], values:[revenue...], confidence:[0..1...] }

    ✅ Multi-item revenue:
      SUM(order_items.line_total) grouped by Product.category
      (filtered by Order.order_date window)
    """
    days = max(int(days), 1)
    since = datetime.utcnow() - timedelta(days=days)

    q = (
        db.session.query(  # type: ignore[attr-defined]
            Product.category.label("category"),
            func.sum(OrderItem.line_total).label("revenue"),
            func.count(func.distinct(Order.id)).label("n"),
        )
        .select_from(Product)
        .join(OrderItem, OrderItem.product_id == Product.id)
        .join(Order, Order.id == OrderItem.order_id)
        .filter(Order.order_date >= since)
        .group_by(Product.category)
        .order_by(desc(func.sum(OrderItem.line_total)))
    )

    rows = q.all()

    labels: List[str] = []
    values: List[float] = []
    confidence: List[float] = []

    for cat, rev, n in rows:
        cat_name = cat or "Uncategorized"
        revenue = float(rev or 0.0)
        nn = int(n or 0)

        labels.append(str(cat_name))
        values.append(round(revenue, 2))
        confidence.append(round(clamp01(min(1.0, 0.25 + (log10(nn + 1) / 2.0))), 3))

    return {"labels": labels, "values": values, "confidence": confidence}
