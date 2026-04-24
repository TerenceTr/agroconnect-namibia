# ============================================================================
# backend/routes/review_analytics.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Review-quality analytics endpoints for farmer and admin dashboards.
#
# PHASE 4B:
#   ✅ Farmer analytics endpoint
#   ✅ Admin analytics endpoint
#   ✅ Complaint charts and filters payload
# ============================================================================

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify

from backend.models.user import User
from backend.services.review_analytics_service import build_review_quality_analytics
from backend.utils.require_auth import require_access_token

review_analytics_bp = Blueprint("review_analytics", __name__)


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def _err(msg: str, status: int):
    resp = jsonify({"success": False, "message": msg})
    resp.status_code = status
    return resp


def _uuid(value: Any) -> Optional[UUID]:
    from uuid import UUID as _UUID

    try:
        raw = str(value or "").strip()
        return _UUID(raw) if raw else None
    except Exception:
        return None


def _safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def _current_user_id(current_user: Any) -> Optional[UUID]:
    return _uuid(getattr(current_user, "id", None) or getattr(current_user, "user_id", None))


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


def _collect_filters() -> dict[str, Any]:
    return {
        "days": request.args.get("days"),
        "bucket": request.args.get("bucket"),
        "product_id": _uuid(request.args.get("product_id") or request.args.get("productId")),
        "taxonomy_code": request.args.get("taxonomy_code") or request.args.get("taxonomyCode"),
        "parent_group": request.args.get("parent_group") or request.args.get("parentGroup"),
        "detected_by": request.args.get("detected_by") or request.args.get("detectedBy"),
        "resolution_status": request.args.get("resolution_status") or request.args.get("resolutionStatus"),
        "verified_only": request.args.get("verified_only") or request.args.get("verifiedOnly"),
        "only_negative": request.args.get("only_negative") or request.args.get("onlyNegative"),
        "min_severity": request.args.get("min_severity") or request.args.get("minSeverity"),
        "repeat_threshold": request.args.get("repeat_threshold") or request.args.get("repeatThreshold"),
    }


# ----------------------------------------------------------------------------
# Farmer analytics
# ----------------------------------------------------------------------------
@review_analytics_bp.get("/farmer/<string:farmer_id>", strict_slashes=False)
@require_access_token
def farmer_review_analytics(farmer_id: str):
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)

    current_uid = _current_user_id(current_user)
    target_farmer_id = _uuid(farmer_id)
    if target_farmer_id is None:
        return _err("Valid farmer_id is required", 400)

    if _current_user_is_admin(current_user):
        pass
    elif _current_user_is_farmer(current_user):
        if current_uid is None or current_uid != target_farmer_id:
            return _err("You can only view analytics for your own account", 403)
    else:
        return _err("Farmer or admin access required", 403)

    payload = build_review_quality_analytics(
        scope="farmer",
        farmer_id=target_farmer_id,
        filters=_collect_filters(),
    )

    return jsonify({"success": True, **payload})


# ----------------------------------------------------------------------------
# Admin analytics
# ----------------------------------------------------------------------------
@review_analytics_bp.get("/admin/overview", strict_slashes=False)
@require_access_token
def admin_review_analytics():
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User) or not _current_user_is_admin(current_user):
        return _err("Admin access required", 403)

    payload = build_review_quality_analytics(
        scope="admin",
        farmer_id=None,
        filters=_collect_filters(),
    )

    return jsonify({"success": True, **payload})
