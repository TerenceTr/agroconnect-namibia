# ============================================================================
# backend/routes/review_quality.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Complaint taxonomy and review-issue-link endpoints.
#
# PHASE 4A:
#   ✅ Public read endpoint for taxonomy
#   ✅ Admin create/update endpoints for taxonomy
#   ✅ Customer / farmer / admin issue-tagging endpoints
#   ✅ Review-linked structured complaint data for later analytics work
#
# IMPORTANT FIXES IN THIS VERSION:
#   ✅ Uses Flask import paths that are friendly to the current type checker
#   ✅ Avoids typed-constructor errors for ComplaintTaxonomy(...)
#   ✅ Avoids typed-constructor errors for ReviewIssueLink(...)
#   ✅ Uses safe attribute assignment for schema-compatible model creation
#
# NOTE:
#   If your app does not auto-register new route modules, register this
#   blueprint at:
#       app.register_blueprint(review_quality_bp, url_prefix="/api/reviews")
# ============================================================================

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import delete, select

from backend.database.db import db
from backend.models.complaint_taxonomy import ComplaintTaxonomy
from backend.models.review_issue_link import ReviewIssueLink
from backend.models.user import User
from backend.utils.require_auth import require_access_token

try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]

review_quality_bp = Blueprint("review_quality", __name__)

ALLOWED_DETECTED_BY = {"customer", "farmer", "admin", "system"}
ALLOWED_PARENT_GROUPS = {
    "product_quality",
    "packaging",
    "fulfilment",
    "service",
    "listing_integrity",
    "platform",
    "other",
}


# ----------------------------------------------------------------------------
# Helper functions
# ----------------------------------------------------------------------------
def _err(msg: str, status: int):
    resp = jsonify({"success": False, "message": msg})
    resp.status_code = status
    return resp


def _uuid(value: Any) -> Optional[UUID]:
    try:
        raw = str(value or "").strip()
        return UUID(raw) if raw else None
    except Exception:
        return None


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


def _first_value(obj: Any, *names: str) -> Any:
    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return None


def _set_first_attr(obj: Any, names: tuple[str, ...], value: Any) -> bool:
    """
    Safely set the first matching attribute name on a model.

    This keeps the route tolerant to small schema naming differences and also
    avoids Pyright complaints about model constructors not exposing named kwargs.
    """
    for name in names:
        if hasattr(obj, name):
            try:
                setattr(obj, name, value)
                return True
            except Exception:
                return False
    return False


def _current_user_id(current_user: Any) -> Optional[UUID]:
    return _uuid(_first_value(current_user, "id", "user_id"))


def _current_user_is_admin(current_user: Any) -> bool:
    if current_user is None:
        return False
    if getattr(current_user, "is_admin", False):
        return True

    role_name = _safe_str(getattr(current_user, "role_name", None)).lower()
    if role_name:
        return role_name == "admin"

    try:
        return int(getattr(current_user, "role", 0) or 0) == 1
    except Exception:
        return False


def _current_user_is_farmer(current_user: Any) -> bool:
    if current_user is None:
        return False
    if getattr(current_user, "is_farmer", False):
        return True

    role_name = _safe_str(getattr(current_user, "role_name", None)).lower()
    if role_name:
        return role_name == "farmer"

    try:
        return int(getattr(current_user, "role", 0) or 0) == 2
    except Exception:
        return False


def _normalize_detected_by(value: Any, default: str = "customer") -> str:
    detected_by = _safe_str(value, default).lower().replace(" ", "_")
    return detected_by if detected_by in ALLOWED_DETECTED_BY else default


def _serialize_issue_links(rating_id: UUID) -> list[dict[str, Any]]:
    rows = db.session.scalars(
        select(ReviewIssueLink)
        .where(ReviewIssueLink.rating_id == rating_id)
        .order_by(ReviewIssueLink.is_primary.desc(), ReviewIssueLink.created_at.asc())
    ).all()
    return [row.to_dict() for row in rows]


def _rating_exists(rating_id: UUID) -> bool:
    if Rating is None:
        return False
    return db.session.get(Rating, rating_id) is not None


# ----------------------------------------------------------------------------
# Taxonomy endpoints
# ----------------------------------------------------------------------------
@review_quality_bp.get("/taxonomy", strict_slashes=False)
def get_complaint_taxonomy():
    include_inactive = _safe_str(request.args.get("include_inactive"), "0").lower() in {
        "1",
        "true",
        "yes",
    }
    parent_group = _safe_str(request.args.get("parent_group"), "").lower()

    stmt = select(ComplaintTaxonomy).order_by(
        ComplaintTaxonomy.parent_group.asc(),
        ComplaintTaxonomy.severity_weight.desc(),
        ComplaintTaxonomy.label.asc(),
    )

    if not include_inactive:
        stmt = stmt.where(ComplaintTaxonomy.is_active.is_(True))

    if parent_group:
        stmt = stmt.where(ComplaintTaxonomy.parent_group == parent_group)

    rows = db.session.scalars(stmt).all()

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row.parent_group, []).append(row.to_dict())

    return jsonify(
        {
            "success": True,
            "items": [row.to_dict() for row in rows],
            "groups": grouped,
        }
    )


@review_quality_bp.post("/taxonomy", strict_slashes=False)
@require_access_token
def create_complaint_taxonomy():
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User) or not _current_user_is_admin(current_user):
        return _err("Admin access required", 403)

    data = request.get_json(silent=True) or {}

    code = _safe_str(data.get("code")).lower().replace(" ", "_")
    label = _safe_str(data.get("label"))
    description = _safe_str(data.get("description")) or None
    parent_group = _safe_str(data.get("parent_group")).lower()
    severity_weight = max(1, min(_safe_int(data.get("severity_weight"), 1), 5))
    is_active = bool(data.get("is_active", True))

    if not code:
        return _err("code is required", 400)
    if not label:
        return _err("label is required", 400)
    if parent_group not in ALLOWED_PARENT_GROUPS:
        return _err("parent_group is invalid", 400)

    existing = db.session.scalar(
        select(ComplaintTaxonomy).where(ComplaintTaxonomy.code == code).limit(1)
    )
    if existing is not None:
        return _err("Taxonomy code already exists", 409)

    # Create the row without named constructor args so the current type checker
    # does not complain about model __init__ signatures.
    row = ComplaintTaxonomy()

    if not _set_first_attr(row, ("code",), code):
        return _err("ComplaintTaxonomy schema mismatch (missing code)", 500)
    if not _set_first_attr(row, ("label",), label):
        return _err("ComplaintTaxonomy schema mismatch (missing label)", 500)
    if not _set_first_attr(row, ("description",), description):
        return _err("ComplaintTaxonomy schema mismatch (missing description)", 500)
    if not _set_first_attr(row, ("parent_group",), parent_group):
        return _err("ComplaintTaxonomy schema mismatch (missing parent_group)", 500)
    if not _set_first_attr(row, ("severity_weight",), severity_weight):
        return _err("ComplaintTaxonomy schema mismatch (missing severity_weight)", 500)
    if not _set_first_attr(row, ("is_active",), is_active):
        return _err("ComplaintTaxonomy schema mismatch (missing is_active)", 500)

    # Some schemas may not auto-fill timestamps in local development.
    if hasattr(row, "created_at") and getattr(row, "created_at", None) is None:
        try:
            setattr(row, "created_at", datetime.utcnow())
        except Exception:
            pass
    if hasattr(row, "updated_at") and getattr(row, "updated_at", None) is None:
        try:
            setattr(row, "updated_at", datetime.utcnow())
        except Exception:
            pass

    db.session.add(row)
    db.session.commit()

    resp = jsonify({"success": True, "item": row.to_dict()})
    resp.status_code = 201
    return resp


@review_quality_bp.patch("/taxonomy/<string:taxonomy_id>", strict_slashes=False)
@require_access_token
def update_complaint_taxonomy(taxonomy_id: str):
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User) or not _current_user_is_admin(current_user):
        return _err("Admin access required", 403)

    tid = _uuid(taxonomy_id)
    if tid is None:
        return _err("Valid taxonomy_id is required", 400)

    row = db.session.get(ComplaintTaxonomy, tid)
    if row is None:
        return _err("Taxonomy item not found", 404)

    data = request.get_json(silent=True) or {}

    if "label" in data:
        label = _safe_str(data.get("label"))
        if not label:
            return _err("label cannot be blank", 400)
        row.label = label

    if "description" in data:
        row.description = _safe_str(data.get("description")) or None

    if "parent_group" in data:
        parent_group = _safe_str(data.get("parent_group")).lower()
        if parent_group not in ALLOWED_PARENT_GROUPS:
            return _err("parent_group is invalid", 400)
        row.parent_group = parent_group

    if "severity_weight" in data:
        row.severity_weight = max(1, min(_safe_int(data.get("severity_weight"), 1), 5))

    if "is_active" in data:
        row.is_active = bool(data.get("is_active"))

    if hasattr(row, "updated_at"):
        row.updated_at = datetime.utcnow()

    db.session.commit()

    return jsonify({"success": True, "item": row.to_dict()})


# ----------------------------------------------------------------------------
# Review issue link endpoints
# ----------------------------------------------------------------------------
@review_quality_bp.get("/<string:rating_id>/issues", strict_slashes=False)
def get_review_issue_links(rating_id: str):
    rid = _uuid(rating_id)
    if rid is None:
        return _err("Valid rating_id is required", 400)

    if not _rating_exists(rid):
        return _err("Review not found", 404)

    return jsonify({"success": True, "items": _serialize_issue_links(rid)})


@review_quality_bp.post("/<string:rating_id>/issues", strict_slashes=False)
@require_access_token
def create_review_issue_links(rating_id: str):
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)

    rid = _uuid(rating_id)
    if rid is None:
        return _err("Valid rating_id is required", 400)

    if not _rating_exists(rid):
        return _err("Review not found", 404)

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated user id not found", 401)

    data = request.get_json(silent=True) or {}
    issues = data.get("issues")

    if not isinstance(issues, list) or not issues:
        return _err("issues must be a non-empty array", 400)

    # Remove existing tags only if explicitly requested.
    replace_existing = bool(data.get("replace_existing", False))
    if replace_existing:
        db.session.execute(delete(ReviewIssueLink).where(ReviewIssueLink.rating_id == rid))

    created_rows: list[ReviewIssueLink] = []
    primary_assigned = False

    for raw_issue in issues:
        taxonomy_id = _uuid(raw_issue.get("taxonomy_id"))
        if taxonomy_id is None:
          return _err("Each issue must include a valid taxonomy_id", 400)

        taxonomy = db.session.get(ComplaintTaxonomy, taxonomy_id)
        if taxonomy is None:
            return _err("One or more taxonomy items were not found", 404)

        detected_by = _normalize_detected_by(raw_issue.get("detected_by"), default="customer")
        confidence_score = max(0.0, min(_safe_float(raw_issue.get("confidence_score"), 1.0), 1.0))
        is_primary = bool(raw_issue.get("is_primary", False)) and not primary_assigned
        notes = _safe_str(raw_issue.get("notes")) or None

        if is_primary:
            primary_assigned = True

        existing = db.session.scalar(
            select(ReviewIssueLink)
            .where(ReviewIssueLink.rating_id == rid)
            .where(ReviewIssueLink.taxonomy_id == taxonomy_id)
            .limit(1)
        )

        if existing is not None:
            existing.detected_by = detected_by
            existing.tagged_by_user_id = current_uid
            existing.confidence_score = confidence_score
            existing.is_primary = is_primary
            existing.notes = notes
            if hasattr(existing, "updated_at"):
                existing.updated_at = datetime.utcnow()
            created_rows.append(existing)
            continue

        # Create the row without named constructor args so the current type
        # checker does not complain about model __init__ signatures.
        row = ReviewIssueLink()

        if not _set_first_attr(row, ("rating_id",), rid):
            return _err("ReviewIssueLink schema mismatch (missing rating_id)", 500)
        if not _set_first_attr(row, ("taxonomy_id",), taxonomy_id):
            return _err("ReviewIssueLink schema mismatch (missing taxonomy_id)", 500)
        if not _set_first_attr(row, ("detected_by",), detected_by):
            return _err("ReviewIssueLink schema mismatch (missing detected_by)", 500)
        if not _set_first_attr(row, ("tagged_by_user_id",), current_uid):
            return _err("ReviewIssueLink schema mismatch (missing tagged_by_user_id)", 500)
        if not _set_first_attr(row, ("confidence_score",), confidence_score):
            return _err("ReviewIssueLink schema mismatch (missing confidence_score)", 500)
        if not _set_first_attr(row, ("is_primary",), is_primary):
            return _err("ReviewIssueLink schema mismatch (missing is_primary)", 500)
        if not _set_first_attr(row, ("notes",), notes):
            return _err("ReviewIssueLink schema mismatch (missing notes)", 500)

        if hasattr(row, "created_at") and getattr(row, "created_at", None) is None:
            try:
                setattr(row, "created_at", datetime.utcnow())
            except Exception:
                pass
        if hasattr(row, "updated_at") and getattr(row, "updated_at", None) is None:
            try:
                setattr(row, "updated_at", datetime.utcnow())
            except Exception:
                pass

        db.session.add(row)
        created_rows.append(row)

    # If no issue was marked as primary, make the first item primary.
    if created_rows and not any(bool(row.is_primary) for row in created_rows):
        created_rows[0].is_primary = True

    db.session.commit()

    return jsonify({"success": True, "items": _serialize_issue_links(rid)})


@review_quality_bp.patch("/<string:rating_id>/issues", strict_slashes=False)
@require_access_token
def update_review_issue_links(rating_id: str):
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)

    # Phase 4A allows farmers and admins to reclassify issue tags.
    if not (_current_user_is_farmer(current_user) or _current_user_is_admin(current_user)):
        return _err("Farmer or admin access required", 403)

    rid = _uuid(rating_id)
    if rid is None:
        return _err("Valid rating_id is required", 400)

    if not _rating_exists(rid):
        return _err("Review not found", 404)

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated user id not found", 401)

    data = request.get_json(silent=True) or {}
    issues = data.get("issues")

    if not isinstance(issues, list) or not issues:
        return _err("issues must be a non-empty array", 400)

    # Full replacement is the cleanest approach for reclassification.
    db.session.execute(delete(ReviewIssueLink).where(ReviewIssueLink.rating_id == rid))

    primary_assigned = False

    for raw_issue in issues:
        taxonomy_id = _uuid(raw_issue.get("taxonomy_id"))
        if taxonomy_id is None:
            return _err("Each issue must include a valid taxonomy_id", 400)

        taxonomy = db.session.get(ComplaintTaxonomy, taxonomy_id)
        if taxonomy is None:
            return _err("One or more taxonomy items were not found", 404)

        requested_detected_by = raw_issue.get("detected_by")
        default_detected_by = "admin" if _current_user_is_admin(current_user) else "farmer"
        detected_by = _normalize_detected_by(requested_detected_by, default=default_detected_by)
        confidence_score = max(0.0, min(_safe_float(raw_issue.get("confidence_score"), 1.0), 1.0))
        is_primary = bool(raw_issue.get("is_primary", False)) and not primary_assigned
        notes = _safe_str(raw_issue.get("notes")) or None

        if is_primary:
            primary_assigned = True

        # Create the row without named constructor args so the current type
        # checker does not complain about model __init__ signatures.
        row = ReviewIssueLink()

        if not _set_first_attr(row, ("rating_id",), rid):
            return _err("ReviewIssueLink schema mismatch (missing rating_id)", 500)
        if not _set_first_attr(row, ("taxonomy_id",), taxonomy_id):
            return _err("ReviewIssueLink schema mismatch (missing taxonomy_id)", 500)
        if not _set_first_attr(row, ("detected_by",), detected_by):
            return _err("ReviewIssueLink schema mismatch (missing detected_by)", 500)
        if not _set_first_attr(row, ("tagged_by_user_id",), current_uid):
            return _err("ReviewIssueLink schema mismatch (missing tagged_by_user_id)", 500)
        if not _set_first_attr(row, ("confidence_score",), confidence_score):
            return _err("ReviewIssueLink schema mismatch (missing confidence_score)", 500)
        if not _set_first_attr(row, ("is_primary",), is_primary):
            return _err("ReviewIssueLink schema mismatch (missing is_primary)", 500)
        if not _set_first_attr(row, ("notes",), notes):
            return _err("ReviewIssueLink schema mismatch (missing notes)", 500)

        if hasattr(row, "created_at") and getattr(row, "created_at", None) is None:
            try:
                setattr(row, "created_at", datetime.utcnow())
            except Exception:
                pass
        if hasattr(row, "updated_at") and getattr(row, "updated_at", None) is None:
            try:
                setattr(row, "updated_at", datetime.utcnow())
            except Exception:
                pass

        db.session.add(row)

    db.session.flush()

    rows = db.session.scalars(
        select(ReviewIssueLink)
        .where(ReviewIssueLink.rating_id == rid)
        .order_by(ReviewIssueLink.created_at.asc())
    ).all()

    if rows and not any(bool(row.is_primary) for row in rows):
        rows[0].is_primary = True

    db.session.commit()

    return jsonify({"success": True, "items": _serialize_issue_links(rid)})