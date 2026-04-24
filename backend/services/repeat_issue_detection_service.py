# ============================================================================
# backend/services/repeat_issue_detection_service.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Repeat issue detection and risk scoring service for Phase 4C.
#
# PHASE 4C:
#   ✅ Service logic for repeat issue detection
#   ✅ Alert thresholds and severity bands
#   ✅ Risk panel payloads for farmer/admin dashboards
#   ✅ Action-oriented recommendations per hotspot
#
# DESIGN:
#   • Builds on Phase 4B review analytics aggregation
#   • Uses repeat_issue_clusters already computed from structured complaint data
#   • Converts raw clusters into risk-scored alerts and dashboard-ready panels
# ============================================================================

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from backend.services.review_analytics_service import build_review_quality_analytics


RISK_THRESHOLDS: dict[str, dict[str, float]] = {
    "low": {"min": 0.0, "max": 2.99},
    "medium": {"min": 3.0, "max": 5.99},
    "high": {"min": 6.0, "max": 8.99},
    "critical": {"min": 9.0, "max": 999999.0},
}


def _safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def _safe_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return fallback


def _safe_float(value: Any, fallback: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return fallback


def _negative_ratio_proxy(avg_rating: Any) -> float:
    rating = max(0.0, min(_safe_float(avg_rating, 0.0), 5.0))
    return max(0.0, min((5.0 - rating) / 4.0, 1.0))


def _risk_score(*, count: int, unresolved_count: int, severity_weight: int, avg_rating: float) -> float:
    negative_ratio = _negative_ratio_proxy(avg_rating)
    score = (
        (count * 0.5)
        + (unresolved_count * 1.2)
        + (severity_weight * 1.5)
        + (negative_ratio * 2.0)
    )
    return round(score, 2)


def _risk_band(score: float) -> str:
    if score >= RISK_THRESHOLDS["critical"]["min"]:
        return "critical"
    if score >= RISK_THRESHOLDS["high"]["min"]:
        return "high"
    if score >= RISK_THRESHOLDS["medium"]["min"]:
        return "medium"
    return "low"


def _recommendation(scope: str, parent_group: str, band: str) -> str:
    scope_label = "product" if scope == "product" else "farmer"
    group = _safe_str(parent_group).lower()

    if band == "critical":
        if group == "product_quality":
            return f"Open an urgent corrective action on the affected {scope_label}, review stock handling, and inspect related batches immediately."
        if group == "packaging":
            return f"Audit packaging materials and dispatch checks for the affected {scope_label}, then verify whether the packaging workflow needs redesign."
        if group == "fulfilment":
            return f"Review fulfilment logs for the affected {scope_label}, verify picking accuracy, and assign a corrective owner today."
        return f"Escalate the affected {scope_label} hotspot for immediate review and assign a corrective action owner."

    if band == "high":
        return f"Create a corrective action for this {scope_label} hotspot and monitor it closely over the next review cycle."
    if band == "medium":
        return f"Track this {scope_label} hotspot and confirm whether current resolution steps reduce recurrence."
    return f"Continue monitoring this {scope_label} hotspot for early warning signals."


def _risk_panels(clusters: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    for cluster in clusters:
        grouped[_safe_str(cluster.get("risk_band"), "low")].append(cluster)

    for items in grouped.values():
        items.sort(key=lambda row: (-_safe_float(row.get("repeat_issue_score"), 0.0), -_safe_int(row.get("count"), 0)))

    return {
        "critical": grouped["critical"][:6],
        "high": grouped["high"][:6],
        "medium": grouped["medium"][:6],
        "low": grouped["low"][:6],
    }


def build_repeat_issue_detection(*, scope: str, farmer_id: Optional[UUID] = None, filters: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    filters = dict(filters or {})
    repeat_threshold = max(2, min(_safe_int(filters.get("repeat_threshold"), 2), 10))
    analytics = build_review_quality_analytics(scope=scope, farmer_id=farmer_id, filters=filters)

    raw_clusters = analytics.get("repeat_issue_clusters") or []
    enriched_clusters: list[dict[str, Any]] = []

    for cluster in raw_clusters:
        count = _safe_int(cluster.get("count"), 0)
        unresolved_count = _safe_int(cluster.get("unresolved_count"), 0)
        severity_weight = max(1, _safe_int(cluster.get("severity_weight"), 1))
        avg_rating = _safe_float(cluster.get("avg_rating"), 0.0)
        score = _risk_score(
            count=count,
            unresolved_count=unresolved_count,
            severity_weight=severity_weight,
            avg_rating=avg_rating,
        )
        band = _risk_band(score)
        recommendation = _recommendation(
            scope=_safe_str(cluster.get("scope"), "product"),
            parent_group=_safe_str(cluster.get("parent_group"), "other"),
            band=band,
        )

        enriched_clusters.append(
            {
                **cluster,
                "repeat_issue_score": score,
                "risk_band": band,
                "risk_level": band,
                "alert_threshold": repeat_threshold,
                "negative_ratio_proxy": round(_negative_ratio_proxy(avg_rating), 2),
                "recommendation": recommendation,
            }
        )

    enriched_clusters.sort(
        key=lambda row: (
            -_safe_float(row.get("repeat_issue_score"), 0.0),
            -_safe_int(row.get("count"), 0),
            -_safe_int(row.get("unresolved_count"), 0),
        )
    )

    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for cluster in enriched_clusters:
        band = _safe_str(cluster.get("risk_band"), "low")
        risk_counts[band] = risk_counts.get(band, 0) + 1

    total = len(enriched_clusters)
    avg_score = round(
        sum(_safe_float(row.get("repeat_issue_score"), 0.0) for row in enriched_clusters) / max(total, 1),
        2,
    ) if enriched_clusters else 0.0
    highest_score = max((_safe_float(row.get("repeat_issue_score"), 0.0) for row in enriched_clusters), default=0.0)

    summary = {
        "total_clusters": total,
        "critical_count": risk_counts.get("critical", 0),
        "high_count": risk_counts.get("high", 0),
        "medium_count": risk_counts.get("medium", 0),
        "low_count": risk_counts.get("low", 0),
        "highest_score": round(highest_score, 2),
        "avg_score": avg_score,
        "threshold": repeat_threshold,
    }

    return {
        "summary": summary,
        "thresholds": RISK_THRESHOLDS,
        "alerts": enriched_clusters[:12],
        "risk_panels": _risk_panels(enriched_clusters),
        "repeat_issue_clusters": enriched_clusters,
        "filters": analytics.get("filters", {}),
        "analytics_summary": analytics.get("summary", {}),
    }


__all__ = ("build_repeat_issue_detection", "RISK_THRESHOLDS")
