# ============================================================================
# backend/services/review_analytics_service.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Complaint / review quality analytics aggregation service.
#
# PHASE 4B:
#   ✅ Farmer analytics aggregation
#   ✅ Admin analytics aggregation
#   ✅ Complaint charts and filter-ready payloads
#   ✅ Repeat issue hotspot detection
#   ✅ Product and farmer breakdowns for dashboarding
#
# DESIGN NOTES:
#   • Uses ComplaintTaxonomy + ReviewIssueLink as the primary structured source
#   • Falls back to legacy Rating.issue_tag when no structured links exist yet
#   • Returns chart-ready arrays so frontend pages stay thin
# ============================================================================

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional
from uuid import UUID

from sqlalchemy import select

from backend.database.db import db
from backend.models.complaint_taxonomy import ComplaintTaxonomy
from backend.models.product import Product
from backend.models.rating import Rating
from backend.models.review_issue_link import ReviewIssueLink


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def _utc_now() -> datetime:
    return datetime.utcnow()


def _safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def _safe_float(value: Any, fallback: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return fallback


def _safe_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return fallback


def _dt_iso(value: Any) -> Optional[str]:
    if isinstance(value, datetime):
        return value.isoformat()
    return None


def _bucket_key(value: Any, bucket: str) -> str:
    if not isinstance(value, datetime):
        return "Unknown"

    if bucket == "month":
        return value.strftime("%Y-%m")
    if bucket == "week":
        year, week, _ = value.isocalendar()
        return f"{year}-W{week:02d}"
    return value.strftime("%Y-%m-%d")


def _sort_bucket_key(label: str) -> tuple[int, int, int]:
    raw = _safe_str(label)
    if "-W" in raw:
        year_part, week_part = raw.split("-W", 1)
        return (_safe_int(year_part, 0), _safe_int(week_part, 0), 0)
    if len(raw) == 7:
        year, month = raw.split("-", 1)
        return (_safe_int(year, 0), _safe_int(month, 0), 0)
    parts = raw.split("-")
    if len(parts) >= 3:
        return (_safe_int(parts[0], 0), _safe_int(parts[1], 0), _safe_int(parts[2], 0))
    return (0, 0, 0)


def _normalize_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    raw = _safe_str(value).lower()
    if raw in {"1", "true", "yes", "y", "on"}:
        return True
    if raw in {"0", "false", "no", "n", "off"}:
        return False
    return default


# ----------------------------------------------------------------------------
# Row structure used inside the service
# ----------------------------------------------------------------------------
@dataclass
class IssueEntry:
    rating_id: str
    product_id: str
    product_name: str
    farmer_id: str
    farmer_name: str
    taxonomy_id: str
    taxonomy_code: str
    taxonomy_label: str
    parent_group: str
    severity_weight: int
    detected_by: str
    confidence_score: float
    is_primary: bool
    notes: Optional[str]
    resolution_status: str
    rating_score: float
    verified_purchase: bool
    created_at: Optional[datetime]
    source: str


# ----------------------------------------------------------------------------
# Query + normalization
# ----------------------------------------------------------------------------
def _taxonomy_maps() -> tuple[dict[str, ComplaintTaxonomy], dict[str, ComplaintTaxonomy], list[ComplaintTaxonomy]]:
    rows = db.session.scalars(
        select(ComplaintTaxonomy).order_by(ComplaintTaxonomy.parent_group.asc(), ComplaintTaxonomy.label.asc())
    ).all()

    by_id: dict[str, ComplaintTaxonomy] = {}
    by_code: dict[str, ComplaintTaxonomy] = {}
    for row in rows:
        key_id = str(getattr(row, "taxonomy_id", "") or "")
        key_code = _safe_str(getattr(row, "code", "")).lower()
        if key_id:
            by_id[key_id] = row
        if key_code:
            by_code[key_code] = row

    return by_id, by_code, rows


def _base_structured_rows(filters: dict[str, Any]) -> list[IssueEntry]:
    stmt = (
        select(ReviewIssueLink, ComplaintTaxonomy, Rating, Product)
        .join(ComplaintTaxonomy, ReviewIssueLink.taxonomy_id == ComplaintTaxonomy.taxonomy_id)
        .join(Rating, ReviewIssueLink.rating_id == Rating.rating_id)
        .join(Product, Rating.product_id == Product.product_id)
    )

    since = filters.get("since")
    if since is not None:
        stmt = stmt.where(Rating.created_at >= since)

    farmer_id = filters.get("farmer_id")
    if farmer_id is not None:
        stmt = stmt.where(Product.user_id == farmer_id)

    product_id = filters.get("product_id")
    if product_id is not None:
        stmt = stmt.where(Product.product_id == product_id)

    taxonomy_code = _safe_str(filters.get("taxonomy_code"), "").lower()
    if taxonomy_code:
        stmt = stmt.where(ComplaintTaxonomy.code == taxonomy_code)

    parent_group = _safe_str(filters.get("parent_group"), "").lower()
    if parent_group:
        stmt = stmt.where(ComplaintTaxonomy.parent_group == parent_group)

    detected_by = _safe_str(filters.get("detected_by"), "").lower()
    if detected_by:
        stmt = stmt.where(ReviewIssueLink.detected_by == detected_by)

    resolution_status = _safe_str(filters.get("resolution_status"), "").lower()
    if resolution_status:
        stmt = stmt.where(Rating.resolution_status == resolution_status)

    if _normalize_bool(filters.get("verified_only"), False):
        stmt = stmt.where(Rating.verified_purchase.is_(True))

    if _normalize_bool(filters.get("only_negative"), False):
        stmt = stmt.where(Rating.rating_score <= 3)

    min_severity = _safe_int(filters.get("min_severity"), 0)
    if min_severity > 0:
        stmt = stmt.where(ComplaintTaxonomy.severity_weight >= min_severity)

    rows = db.session.execute(stmt).all()

    out: list[IssueEntry] = []
    for link, taxonomy, rating, product in rows:
        farmer_obj = getattr(product, "farmer", None)
        out.append(
            IssueEntry(
                rating_id=str(getattr(rating, "rating_id", getattr(rating, "id", "")) or ""),
                product_id=str(getattr(product, "product_id", "") or ""),
                product_name=_safe_str(getattr(product, "product_name", None) or getattr(product, "name", None), "Product"),
                farmer_id=str(getattr(product, "user_id", "") or ""),
                farmer_name=_safe_str(
                    getattr(farmer_obj, "full_name", None)
                    or getattr(farmer_obj, "name", None)
                    or getattr(farmer_obj, "email", None),
                    "Farmer",
                ),
                taxonomy_id=str(getattr(taxonomy, "taxonomy_id", "") or ""),
                taxonomy_code=_safe_str(getattr(taxonomy, "code", None)).lower(),
                taxonomy_label=_safe_str(getattr(taxonomy, "label", None), "Uncategorized"),
                parent_group=_safe_str(getattr(taxonomy, "parent_group", None), "other"),
                severity_weight=max(1, _safe_int(getattr(taxonomy, "severity_weight", 1), 1)),
                detected_by=_safe_str(getattr(link, "detected_by", None), "system"),
                confidence_score=max(0.0, min(_safe_float(getattr(link, "confidence_score", 1.0), 1.0), 1.0)),
                is_primary=bool(getattr(link, "is_primary", False)),
                notes=_safe_str(getattr(link, "notes", None)) or None,
                resolution_status=_safe_str(getattr(rating, "resolution_status", None), "open"),
                rating_score=_safe_float(getattr(rating, "rating_score", 0), 0.0),
                verified_purchase=bool(getattr(rating, "verified_purchase", False)),
                created_at=getattr(rating, "created_at", None),
                source="structured_link",
            )
        )
    return out


def _legacy_issue_rows(filters: dict[str, Any], linked_rating_ids: set[str], taxonomy_by_code: dict[str, ComplaintTaxonomy]) -> list[IssueEntry]:
    stmt = select(Rating, Product).join(Product, Rating.product_id == Product.product_id)

    since = filters.get("since")
    if since is not None:
        stmt = stmt.where(Rating.created_at >= since)

    farmer_id = filters.get("farmer_id")
    if farmer_id is not None:
        stmt = stmt.where(Product.user_id == farmer_id)

    product_id = filters.get("product_id")
    if product_id is not None:
        stmt = stmt.where(Product.product_id == product_id)

    stmt = stmt.where(Rating.issue_tag.is_not(None))

    resolution_status = _safe_str(filters.get("resolution_status"), "").lower()
    if resolution_status:
        stmt = stmt.where(Rating.resolution_status == resolution_status)

    if _normalize_bool(filters.get("verified_only"), False):
        stmt = stmt.where(Rating.verified_purchase.is_(True))

    if _normalize_bool(filters.get("only_negative"), False):
        stmt = stmt.where(Rating.rating_score <= 3)

    rows = db.session.execute(stmt).all()

    taxonomy_code_filter = _safe_str(filters.get("taxonomy_code"), "").lower()
    parent_group_filter = _safe_str(filters.get("parent_group"), "").lower()
    min_severity = _safe_int(filters.get("min_severity"), 0)

    out: list[IssueEntry] = []
    for rating, product in rows:
        rating_id = str(getattr(rating, "rating_id", getattr(rating, "id", "")) or "")
        if not rating_id or rating_id in linked_rating_ids:
            continue

        raw_code = _safe_str(getattr(rating, "issue_tag", None)).lower()
        if not raw_code:
            continue

        taxonomy = taxonomy_by_code.get(raw_code)
        taxonomy_label = raw_code.replace("_", " ").title() or "Uncategorized"
        parent_group = _safe_str(getattr(taxonomy, "parent_group", None), "other") if taxonomy else "other"
        severity_weight = max(1, _safe_int(getattr(taxonomy, "severity_weight", 1), 1)) if taxonomy else 1
        taxonomy_id = str(getattr(taxonomy, "taxonomy_id", "") or "") if taxonomy else ""

        if taxonomy_code_filter and raw_code != taxonomy_code_filter:
            continue
        if parent_group_filter and parent_group != parent_group_filter:
            continue
        if min_severity > 0 and severity_weight < min_severity:
            continue

        farmer_obj = getattr(product, "farmer", None)
        out.append(
            IssueEntry(
                rating_id=rating_id,
                product_id=str(getattr(product, "product_id", "") or ""),
                product_name=_safe_str(getattr(product, "product_name", None) or getattr(product, "name", None), "Product"),
                farmer_id=str(getattr(product, "user_id", "") or ""),
                farmer_name=_safe_str(
                    getattr(farmer_obj, "full_name", None)
                    or getattr(farmer_obj, "name", None)
                    or getattr(farmer_obj, "email", None),
                    "Farmer",
                ),
                taxonomy_id=taxonomy_id,
                taxonomy_code=raw_code,
                taxonomy_label=taxonomy_label,
                parent_group=parent_group,
                severity_weight=severity_weight,
                detected_by="system",
                confidence_score=0.75,
                is_primary=True,
                notes=None,
                resolution_status=_safe_str(getattr(rating, "resolution_status", None), "open"),
                rating_score=_safe_float(getattr(rating, "rating_score", 0), 0.0),
                verified_purchase=bool(getattr(rating, "verified_purchase", False)),
                created_at=getattr(rating, "created_at", None),
                source="legacy_issue_tag",
            )
        )

    return out


# ----------------------------------------------------------------------------
# Aggregation
# ----------------------------------------------------------------------------
def _build_breakdown(entries: Iterable[IssueEntry], key_getter) -> list[dict[str, Any]]:
    bucket: dict[str, dict[str, Any]] = {}

    for entry in entries:
        key = _safe_str(key_getter(entry), "Unknown")
        row = bucket.setdefault(
            key,
            {
                "key": key,
                "label": key,
                "count": 0,
                "weighted_score": 0.0,
                "avg_rating_sum": 0.0,
                "avg_rating_count": 0,
                "resolved_count": 0,
                "unresolved_count": 0,
            },
        )
        row["count"] += 1
        row["weighted_score"] += entry.severity_weight * max(entry.confidence_score, 0.1)
        row["avg_rating_sum"] += entry.rating_score
        row["avg_rating_count"] += 1
        if entry.resolution_status == "resolved":
            row["resolved_count"] += 1
        else:
            row["unresolved_count"] += 1

    out: list[dict[str, Any]] = []
    for row in bucket.values():
        out.append(
            {
                "key": row["key"],
                "label": row["label"],
                "count": row["count"],
                "weighted_score": round(row["weighted_score"], 2),
                "avg_rating": round(row["avg_rating_sum"] / max(row["avg_rating_count"], 1), 2),
                "resolved_count": row["resolved_count"],
                "unresolved_count": row["unresolved_count"],
            }
        )

    out.sort(key=lambda item: (-_safe_int(item.get("count"), 0), _safe_str(item.get("label"))))
    return out


def _trend(entries: Iterable[IssueEntry], bucket: str) -> list[dict[str, Any]]:
    series: dict[str, dict[str, Any]] = {}
    for entry in entries:
        label = _bucket_key(entry.created_at, bucket)
        row = series.setdefault(label, {"bucket": label, "count": 0, "weighted_score": 0.0})
        row["count"] += 1
        row["weighted_score"] += entry.severity_weight * max(entry.confidence_score, 0.1)

    rows = list(series.values())
    rows.sort(key=lambda item: _sort_bucket_key(_safe_str(item.get("bucket"))))
    return [
        {
            "bucket": row["bucket"],
            "count": row["count"],
            "weighted_score": round(_safe_float(row["weighted_score"]), 2),
        }
        for row in rows
    ]


def _product_breakdown(entries: list[IssueEntry]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for entry in entries:
        row = grouped.setdefault(
            entry.product_id,
            {
                "product_id": entry.product_id,
                "product_name": entry.product_name,
                "farmer_id": entry.farmer_id,
                "farmer_name": entry.farmer_name,
                "count": 0,
                "weighted_score": 0.0,
                "resolved_count": 0,
                "unresolved_count": 0,
                "rating_sum": 0.0,
                "rating_count": 0,
                "taxonomy_counts": defaultdict(int),
            },
        )
        row["count"] += 1
        row["weighted_score"] += entry.severity_weight * max(entry.confidence_score, 0.1)
        row["rating_sum"] += entry.rating_score
        row["rating_count"] += 1
        row["taxonomy_counts"][entry.taxonomy_code] += 1
        if entry.resolution_status == "resolved":
            row["resolved_count"] += 1
        else:
            row["unresolved_count"] += 1

    out: list[dict[str, Any]] = []
    for row in grouped.values():
        top_issue_code, top_issue_count = "", 0
        repeat_issue_count = 0
        for code, count in row["taxonomy_counts"].items():
            if count > top_issue_count:
                top_issue_code, top_issue_count = code, count
            if count >= 2:
                repeat_issue_count += 1

        out.append(
            {
                "product_id": row["product_id"],
                "product_name": row["product_name"],
                "farmer_id": row["farmer_id"],
                "farmer_name": row["farmer_name"],
                "count": row["count"],
                "weighted_score": round(row["weighted_score"], 2),
                "avg_rating": round(row["rating_sum"] / max(row["rating_count"], 1), 2),
                "resolved_count": row["resolved_count"],
                "unresolved_count": row["unresolved_count"],
                "top_issue_code": top_issue_code,
                "top_issue_count": top_issue_count,
                "repeat_issue_count": repeat_issue_count,
            }
        )

    out.sort(key=lambda item: (-_safe_int(item.get("count"), 0), _safe_str(item.get("product_name"))))
    return out


def _farmer_breakdown(entries: list[IssueEntry]) -> list[dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    for entry in entries:
        row = grouped.setdefault(
            entry.farmer_id,
            {
                "farmer_id": entry.farmer_id,
                "farmer_name": entry.farmer_name,
                "count": 0,
                "weighted_score": 0.0,
                "resolved_count": 0,
                "unresolved_count": 0,
                "rating_sum": 0.0,
                "rating_count": 0,
                "products": set(),
                "taxonomy_counts": defaultdict(int),
            },
        )
        row["count"] += 1
        row["weighted_score"] += entry.severity_weight * max(entry.confidence_score, 0.1)
        row["rating_sum"] += entry.rating_score
        row["rating_count"] += 1
        row["products"].add(entry.product_id)
        row["taxonomy_counts"][entry.taxonomy_code] += 1
        if entry.resolution_status == "resolved":
            row["resolved_count"] += 1
        else:
            row["unresolved_count"] += 1

    out: list[dict[str, Any]] = []
    for row in grouped.values():
        top_issue_code, top_issue_count = "", 0
        repeat_issue_count = 0
        for code, count in row["taxonomy_counts"].items():
            if count > top_issue_count:
                top_issue_code, top_issue_count = code, count
            if count >= 2:
                repeat_issue_count += 1

        out.append(
            {
                "farmer_id": row["farmer_id"],
                "farmer_name": row["farmer_name"],
                "count": row["count"],
                "weighted_score": round(row["weighted_score"], 2),
                "avg_rating": round(row["rating_sum"] / max(row["rating_count"], 1), 2),
                "resolved_count": row["resolved_count"],
                "unresolved_count": row["unresolved_count"],
                "product_count": len(row["products"]),
                "top_issue_code": top_issue_code,
                "top_issue_count": top_issue_count,
                "repeat_issue_count": repeat_issue_count,
            }
        )

    out.sort(key=lambda item: (-_safe_int(item.get("count"), 0), _safe_str(item.get("farmer_name"))))
    return out


def _repeat_issue_clusters(entries: list[IssueEntry], scope: str, threshold: int = 2) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}

    for entry in entries:
        if scope == "farmer":
            key = (entry.farmer_id, entry.taxonomy_code)
            entity_id = entry.farmer_id
            entity_name = entry.farmer_name
        else:
            key = (entry.product_id, entry.taxonomy_code)
            entity_id = entry.product_id
            entity_name = entry.product_name

        row = grouped.setdefault(
            key,
            {
                "scope": scope,
                "entity_id": entity_id,
                "entity_name": entity_name,
                "taxonomy_code": entry.taxonomy_code,
                "taxonomy_label": entry.taxonomy_label,
                "parent_group": entry.parent_group,
                "severity_weight": entry.severity_weight,
                "count": 0,
                "unresolved_count": 0,
                "rating_sum": 0.0,
                "rating_count": 0,
            },
        )
        row["count"] += 1
        row["rating_sum"] += entry.rating_score
        row["rating_count"] += 1
        if entry.resolution_status != "resolved":
            row["unresolved_count"] += 1

    out: list[dict[str, Any]] = []
    for row in grouped.values():
        if row["count"] < threshold:
            continue
        out.append(
            {
                "scope": row["scope"],
                "entity_id": row["entity_id"],
                "entity_name": row["entity_name"],
                "taxonomy_code": row["taxonomy_code"],
                "taxonomy_label": row["taxonomy_label"],
                "parent_group": row["parent_group"],
                "severity_weight": row["severity_weight"],
                "count": row["count"],
                "unresolved_count": row["unresolved_count"],
                "avg_rating": round(row["rating_sum"] / max(row["rating_count"], 1), 2),
            }
        )

    out.sort(key=lambda item: (-_safe_int(item.get("count"), 0), -_safe_int(item.get("severity_weight"), 0)))
    return out


def _resolution_breakdown(entries: list[IssueEntry]) -> list[dict[str, Any]]:
    return _build_breakdown(entries, lambda entry: entry.resolution_status)


def _detected_by_breakdown(entries: list[IssueEntry]) -> list[dict[str, Any]]:
    return _build_breakdown(entries, lambda entry: entry.detected_by)


def _taxonomy_breakdown(entries: list[IssueEntry]) -> list[dict[str, Any]]:
    rows = _build_breakdown(entries, lambda entry: entry.taxonomy_code)
    for row in rows:
        first = next((e for e in entries if e.taxonomy_code == row["key"]), None)
        if first is not None:
            row["taxonomy_code"] = first.taxonomy_code
            row["taxonomy_label"] = first.taxonomy_label
            row["parent_group"] = first.parent_group
            row["severity_weight"] = first.severity_weight
            row["label"] = first.taxonomy_label
    return rows


def _parent_group_breakdown(entries: list[IssueEntry]) -> list[dict[str, Any]]:
    rows = _build_breakdown(entries, lambda entry: entry.parent_group)
    for row in rows:
        row["parent_group"] = row["key"]
    return rows


def _summary(entries: list[IssueEntry], repeat_issue_clusters: list[dict[str, Any]]) -> dict[str, Any]:
    unique_reviews = {entry.rating_id for entry in entries if entry.rating_id}
    unique_products = {entry.product_id for entry in entries if entry.product_id}
    unique_farmers = {entry.farmer_id for entry in entries if entry.farmer_id}
    verified_count = sum(1 for entry in entries if entry.verified_purchase)
    unresolved_count = sum(1 for entry in entries if entry.resolution_status != "resolved")
    total_score = sum(entry.rating_score for entry in entries)
    avg_rating = round(total_score / len(entries), 2) if entries else 0.0
    avg_severity = round(sum(entry.severity_weight for entry in entries) / len(entries), 2) if entries else 0.0
    weighted_issue_score = round(
        sum(entry.severity_weight * max(entry.confidence_score, 0.1) for entry in entries),
        2,
    )

    top_parent_group = None
    parent_rows = _parent_group_breakdown(entries)
    if parent_rows:
        top_parent_group = parent_rows[0].get("parent_group")

    return {
        "complaint_count": len(entries),
        "review_count": len(unique_reviews),
        "product_count": len(unique_products),
        "farmer_count": len(unique_farmers),
        "verified_count": verified_count,
        "unresolved_count": unresolved_count,
        "avg_rating": avg_rating,
        "avg_severity": avg_severity,
        "weighted_issue_score": weighted_issue_score,
        "repeat_issue_cluster_count": len(repeat_issue_clusters),
        "top_parent_group": top_parent_group,
    }


def _filters_payload(taxonomy_rows: list[ComplaintTaxonomy]) -> dict[str, Any]:
    parent_groups = sorted({row.parent_group for row in taxonomy_rows if _safe_str(row.parent_group)})
    taxonomy_items = [row.to_dict() for row in taxonomy_rows]
    return {
        "parent_groups": parent_groups,
        "taxonomy_items": taxonomy_items,
        "resolution_statuses": ["open", "acknowledged", "in_progress", "resolved"],
        "detected_by_values": ["customer", "farmer", "admin", "system"],
    }


def build_review_quality_analytics(*, scope: str, farmer_id: Optional[UUID] = None, filters: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    filters = dict(filters or {})
    days = max(7, min(_safe_int(filters.get("days"), 60), 365))
    filters["since"] = _utc_now() - timedelta(days=days)
    filters["farmer_id"] = farmer_id

    bucket = _safe_str(filters.get("bucket"), "week").lower()
    if bucket not in {"day", "week", "month"}:
        bucket = "week"

    repeat_threshold = max(2, min(_safe_int(filters.get("repeat_threshold"), 2), 10))

    _taxonomy_by_id, taxonomy_by_code, taxonomy_rows = _taxonomy_maps()

    structured = _base_structured_rows(filters)
    linked_rating_ids = {entry.rating_id for entry in structured}
    legacy = _legacy_issue_rows(filters, linked_rating_ids, taxonomy_by_code)

    entries = structured + legacy

    taxonomy_breakdown = _taxonomy_breakdown(entries)
    parent_group_breakdown = _parent_group_breakdown(entries)
    resolution_breakdown = _resolution_breakdown(entries)
    detected_by_breakdown = _detected_by_breakdown(entries)
    product_breakdown = _product_breakdown(entries)
    farmer_breakdown = _farmer_breakdown(entries)

    repeat_issue_clusters = _repeat_issue_clusters(
        entries,
        "product" if scope == "farmer" else "farmer",
        threshold=repeat_threshold,
    )

    return {
        "summary": _summary(entries, repeat_issue_clusters),
        "trend": _trend(entries, bucket),
        "taxonomy_breakdown": taxonomy_breakdown,
        "parent_group_breakdown": parent_group_breakdown,
        "resolution_breakdown": resolution_breakdown,
        "detected_by_breakdown": detected_by_breakdown,
        "product_breakdown": product_breakdown,
        "farmer_breakdown": farmer_breakdown if scope == "admin" else [],
        "repeat_issue_clusters": repeat_issue_clusters,
        "filters": {
            **_filters_payload(taxonomy_rows),
            "applied": {
                "days": days,
                "bucket": bucket,
                "product_id": str(filters.get("product_id")) if filters.get("product_id") else None,
                "taxonomy_code": _safe_str(filters.get("taxonomy_code")) or None,
                "parent_group": _safe_str(filters.get("parent_group")) or None,
                "detected_by": _safe_str(filters.get("detected_by")) or None,
                "resolution_status": _safe_str(filters.get("resolution_status")) or None,
                "verified_only": _normalize_bool(filters.get("verified_only"), False),
                "only_negative": _normalize_bool(filters.get("only_negative"), False),
                "min_severity": _safe_int(filters.get("min_severity"), 0),
                "repeat_threshold": repeat_threshold,
            },
        },
    }


__all__ = ("build_review_quality_analytics",)
