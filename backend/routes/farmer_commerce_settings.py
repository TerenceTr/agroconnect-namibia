# ============================================================================
# backend/routes/farmer_commerce_settings.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Farmer-specific commerce settings API.
#
# ROUTES:
#   GET /api/farmers/settings/me
#   PUT /api/farmers/settings/me
#   GET /api/farmers/settings
#   PUT /api/farmers/settings
#
# PURPOSE:
#   Complements farmer_payment_profile.py by persisting non-bank seller controls
#   such as storefront, fulfillment, notifications, communication preferences,
#   analytics visibility, and business profile metadata.
#
# PYRIGHT FIX IN THIS UPDATE:
#   The route helper can return:
#     • a real farmer UUID, or
#     • an error payload
#   Even after checking `error`, static typing still sees `farmer_id` as
#   Optional[UUID]. We therefore add an explicit non-None guard before calling:
#     • read_farmer_commerce_settings(...)
#     • write_farmer_commerce_settings(...)
#
#   This removes errors like:
#     Argument of type "UUID | None" cannot be assigned to parameter
#     "farmer_id" of type "UUID | str"
# ============================================================================

from __future__ import annotations

from functools import wraps
from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify

from backend.models.user import ROLE_ADMIN, User
from backend.services.farmer_commerce_settings import (
    default_farmer_commerce_settings,
    normalize_farmer_commerce_settings,
    read_farmer_commerce_settings,
    write_farmer_commerce_settings,
)
from backend.utils.require_auth import require_access_token

farmer_commerce_settings_bp = Blueprint("farmer_commerce_settings", __name__)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _safe_str(v: Any) -> Optional[str]:
    """Return a trimmed string or None."""
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _as_uuid(v: Any) -> Optional[UUID]:
    """Best-effort UUID coercion."""
    if isinstance(v, UUID):
        return v
    s = _safe_str(v)
    if not s:
        return None
    try:
        return UUID(s)
    except Exception:
        return None


def _is_admin(user: User) -> bool:
    """Support both numeric role ids and string role names."""
    raw_role = getattr(user, "role", None)
    role_name = _safe_str(getattr(user, "role_name", None) or getattr(user, "roleName", None))

    try:
        if raw_role is not None and int(raw_role) == int(ROLE_ADMIN):
            return True
    except Exception:
        pass

    return (role_name or _safe_str(raw_role) or "").lower() == "admin"


def _is_farmer(user: User) -> bool:
    """Support both numeric role ids and string role names."""
    raw_role = getattr(user, "role", None)
    role_name = _safe_str(getattr(user, "role_name", None) or getattr(user, "roleName", None))

    try:
        # In this project, farmer is role 2.
        if raw_role is not None and int(raw_role) == 2:
            return True
    except Exception:
        pass

    return (role_name or _safe_str(raw_role) or "").lower() == "farmer"


def _user_id(user: User) -> Optional[UUID]:
    """Extract the authenticated user's UUID from common identity fields."""
    return (
        _as_uuid(getattr(user, "id", None))
        or _as_uuid(getattr(user, "user_id", None))
        or _as_uuid(getattr(user, "userId", None))
        or _as_uuid(getattr(user, "sub", None))
    )


def _resolve_target_farmer_id(
    current_user: User,
) -> tuple[Optional[UUID], Optional[tuple[dict[str, object], int]]]:
    """
    Resolve which farmer's settings are being read/written.

    Rules:
      • Farmers can only read/write their own settings.
      • Admins may read/write a specific farmer via ?farmer_id=...
      • If no farmer_id is supplied, the current authenticated user's id is used.
    """
    current_uid = _user_id(current_user)
    if current_uid is None:
        return None, ({"ok": False, "message": "Invalid authenticated user context"}, 401)

    requested = _as_uuid(request.args.get("farmer_id") or request.args.get("farmerId"))

    if requested is not None:
        if _is_admin(current_user):
            return requested, None

        if requested != current_uid:
            return None, ({"ok": False, "message": "Forbidden"}, 403)

    if not (_is_farmer(current_user) or _is_admin(current_user)):
        return None, ({"ok": False, "message": "Farmer access required"}, 403)

    return requested or current_uid, None


def token_required(fn):
    """Attach JWT guard and pass the resolved current user to the route."""
    @wraps(fn)
    @require_access_token
    def wrapper(*args, **kwargs):
        user = getattr(request, "current_user", None)
        if not isinstance(user, User):
            return jsonify({"ok": False, "message": "Unauthorized"}), 401
        return fn(user, *args, **kwargs)

    return wrapper


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@farmer_commerce_settings_bp.get("/settings")
@farmer_commerce_settings_bp.get("/settings/me")
@token_required
def get_my_farmer_settings(current_user: User):
    """
    Return the current farmer's commerce settings.

    Pyright note:
      Even after `if error: ...`, `farmer_id` is still typed as Optional[UUID].
      We therefore add an explicit non-None guard before using it.
    """
    farmer_id, error = _resolve_target_farmer_id(current_user)
    if error:
        payload, status = error
        return jsonify(payload), status

    if farmer_id is None:
        return jsonify({"ok": False, "message": "Could not resolve farmer id"}), 400

    settings = read_farmer_commerce_settings(farmer_id)

    return jsonify(
        {
            "ok": True,
            "data": settings,
            "defaults": default_farmer_commerce_settings(),
            "farmer_id": str(farmer_id),
        }
    ), 200


@farmer_commerce_settings_bp.put("/settings")
@farmer_commerce_settings_bp.put("/settings/me")
@token_required
def save_my_farmer_settings(current_user: User):
    """
    Save the current farmer's commerce settings.

    Payload shapes supported:
      • { ...settings }
      • { "settings": { ...settings } }
    """
    farmer_id, error = _resolve_target_farmer_id(current_user)
    if error:
        payload, status = error
        return jsonify(payload), status

    if farmer_id is None:
        return jsonify({"ok": False, "message": "Could not resolve farmer id"}), 400

    body = request.get_json(silent=True) or {}
    if not isinstance(body, dict):
        body = {}

    payload = body.get("settings") if isinstance(body.get("settings"), dict) else body

    # Normalize and merge with project defaults before persisting.
    merged = normalize_farmer_commerce_settings(payload)
    saved = write_farmer_commerce_settings(farmer_id, merged)

    return jsonify(
        {
            "ok": True,
            "message": "Farmer commerce settings updated successfully.",
            "data": saved,
            "farmer_id": str(farmer_id),
        }
    ), 200