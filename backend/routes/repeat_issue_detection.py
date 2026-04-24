# ============================================================================
# backend/routes/repeat_issue_detection.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Repeat issue detection endpoints for Phase 4C.
#
# PHASE 4C:
#   ✅ Farmer repeat issue alerts endpoint
#   ✅ Admin repeat issue alerts endpoint
#   ✅ Alert thresholds and risk summaries
# ============================================================================

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify

from backend.models.user import User
from backend.services.repeat_issue_detection_service import build_repeat_issue_detection
from backend.utils.require_auth import require_access_token

repeat_issue_detection_bp = Blueprint("repeat_issue_detection", __name__)


def _safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def _safe_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return fallback


def _safe_bool(value: Any, default: bool = False) -> bool:
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


def _uuid(value: Any) -> Optional[UUID]:
    try:
        raw = _safe_str(value)
        return UUID(raw) if raw else None
    except Exception:
        return None


def _current_user_id(current_user: Any) -> Optional[UUID]:
    raw = getattr(current_user, "id", None) or getattr(current_user, "user_id", None)
    return _uuid(raw)


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


def _err(msg: str, status: int):
    resp = jsonify({"success": False, "message": msg})
    resp.status_code = status
    return resp


def _parse_filters() -> dict[str, Any]:
    return {
        "days": _safe_int(request.args.get("days"), 60),
        "bucket": _safe_str(request.args.get("bucket"), "week"),
        "product_id": _uuid(request.args.get("product_id") or request.args.get("productId")),
        "taxonomy_code": _safe_str(request.args.get("taxonomy_code") or request.args.get("taxonomyCode")),
        "parent_group": _safe_str(request.args.get("parent_group") or request.args.get("parentGroup")),
        "detected_by": _safe_str(request.args.get("detected_by") or request.args.get("detectedBy")),
        "resolution_status": _safe_str(request.args.get("resolution_status") or request.args.get("resolutionStatus")),
        "verified_only": _safe_bool(request.args.get("verified_only") or request.args.get("verifiedOnly"), False),
        "only_negative": _safe_bool(request.args.get("only_negative") or request.args.get("onlyNegative"), False),
        "min_severity": _safe_int(request.args.get("min_severity") or request.args.get("minSeverity"), 0),
        "repeat_threshold": _safe_int(request.args.get("repeat_threshold") or request.args.get("repeatThreshold"), 2),
    }


@repeat_issue_detection_bp.get("/farmer/<string:farmer_id>/repeat-issues", strict_slashes=False)
@require_access_token
def farmer_repeat_issues(farmer_id: str):
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)

    requested_farmer_id = _uuid(farmer_id)
    if requested_farmer_id is None:
        return _err("Valid farmer_id is required", 400)

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated user id not found", 401)

    if not (_current_user_is_admin(current_user) or (_current_user_is_farmer(current_user) and current_uid == requested_farmer_id)):
        return _err("You can only view repeat issue alerts for your own farmer account", 403)

    payload = build_repeat_issue_detection(
        scope="farmer",
        farmer_id=requested_farmer_id,
        filters=_parse_filters(),
    )
    return jsonify({"success": True, **payload})


@repeat_issue_detection_bp.get("/admin/repeat-issues", strict_slashes=False)
@require_access_token
def admin_repeat_issues():
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User) or not _current_user_is_admin(current_user):
        return _err("Admin access required", 403)

    payload = build_repeat_issue_detection(
        scope="admin",
        farmer_id=None,
        filters=_parse_filters(),
    )
    return jsonify({"success": True, **payload})
