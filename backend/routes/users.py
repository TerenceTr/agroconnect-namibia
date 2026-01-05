# =====================================================================
# backend/routes/users.py — User Management API (PYRIGHT-CLEAN + DB-ALIGNED)
# ---------------------------------------------------------------------
# FILE ROLE:
#   User listing + profile update endpoints for AgroConnect Namibia.
#
#   Provides:
#     • GET  /api/users/            -> list active users
#     • GET  /api/users/<user_id>   -> fetch an active user by UUID
#     • PUT  /api/users/<user_id>   -> update allowed user fields safely
#
# DB-ALIGNED NOTE (IMPORTANT):
#   Your current User model defines:
#     email: Mapped[str] with nullable=False
#   Therefore:
#     • email MUST always be a string (never None)
#     • update endpoint must not assign None to user.email
#
# RELIABILITY GOALS:
#   • Never crash on invalid JSON / invalid UUID
#   • Avoid Optional attribute issues (Pyright/Pylance clean)
#   • Enforce uniqueness constraints safely
# =====================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import select

from backend.database.db import db
from backend.models.user import User
from backend.utils.validators import validate_phone

# Registered with url_prefix="/api/users" in backend/routes/__init__.py
users_bp = Blueprint("users", __name__)


# --------------------------------------------------------------------
# Response helpers
# --------------------------------------------------------------------
def _json_error(message: str, status: int) -> Any:
    """Consistent JSON error response."""
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


def _json_ok(payload: dict[str, Any], status: int = 200) -> Any:
    """Consistent JSON success response."""
    resp = jsonify({"success": True, **payload})
    resp.status_code = status
    return resp


# --------------------------------------------------------------------
# ID + load helpers
# --------------------------------------------------------------------
def _try_uuid(value: Any) -> Optional[uuid.UUID]:
    """Parse UUID from any input; return None if invalid."""
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _load_user_by_uuid(user_id: Any) -> Optional[User]:
    """
    Load a user by UUID primary key.
    Returns None if:
      • invalid UUID
      • no user found
    """
    uid = _try_uuid(user_id)
    if uid is None:
        return None
    return db.session.get(User, uid)


def _load_active_user(user_id: Any) -> Optional[User]:
    """
    Load a user and treat inactive users as "not found" for this API.
    Returns a real User only if:
      • user exists
      • user.is_active is True
    """
    user = _load_user_by_uuid(user_id)
    if user is None:
        return None
    if not bool(getattr(user, "is_active", True)):
        return None
    return user


def _json_object_body() -> tuple[dict[str, Any], Optional[Any]]:
    """
    Safely read a JSON body and guarantee it's a dict.

    Returns:
      (data_dict, error_response)
      • If error_response is not None, return it from the route immediately.
    """
    raw = request.get_json(silent=True)

    if raw is None:
        return {}, None

    if not isinstance(raw, dict):
        return {}, _json_error("JSON body must be an object", 400)

    return raw, None


# ====================================================================
# LIST USERS
# ====================================================================
@users_bp.get("/")
def list_users() -> Any:
    """
    List active users only.
    """
    stmt = select(User).where(User.is_active.is_(True)).order_by(User.created_at.desc())
    users = db.session.scalars(stmt).all()
    return _json_ok({"users": [u.to_dict() for u in users]}, 200)


# ====================================================================
# GET USER
# ====================================================================
@users_bp.get("/<string:user_id>")
def get_user(user_id: str) -> Any:
    """
    Get one active user by UUID.
    """
    user = _load_active_user(user_id)
    if user is None:
        return _json_error("User not found", 404)

    return _json_ok({"user": user.to_dict()}, 200)


# ====================================================================
# UPDATE USER
# ====================================================================
@users_bp.put("/<string:user_id>")
def update_user(user_id: str) -> Any:
    """
    Update an active user.

    Allowed fields:
      • full_name
      • phone
      • email       (REQUIRED STRING in your DB model; never None)
      • location
      • is_active   (optional; remove if you don't want this endpoint to toggle)
    """
    user = _load_active_user(user_id)
    if user is None:
        return _json_error("User not found", 404)

    data, err = _json_object_body()
    if err is not None:
        return err

    # ----------------------------
    # Full name
    # ----------------------------
    if "full_name" in data:
        full = str(data.get("full_name") or "").strip()
        if len(full) < 3:
            return _json_error("Full name too short", 400)
        user.full_name = full

    # ----------------------------
    # Phone (validated + unique)
    # ----------------------------
    if "phone" in data:
        validated_phone = validate_phone(data.get("phone"))
        if validated_phone is None:
            return _json_error("Invalid phone number", 400)

        # Unique check (excluding self)
        existing = db.session.scalars(
            select(User).where(User.phone == validated_phone, User.id != user.id)
        ).first()
        if existing is not None:
            return _json_error("Phone already in use", 409)

        user.phone = validated_phone

    # ----------------------------
    # Email (DB-aligned: NOT NULL + unique)
    # ----------------------------
    if "email" in data:
        # IMPORTANT:
        #   User.email is Mapped[str] nullable=False in your model.
        #   So we must NEVER assign None here.
        raw_email = str(data.get("email") or "").strip()

        if not raw_email:
            return _json_error("Email is required and cannot be empty", 400)

        # Optional (light) validation: ensure it looks like an email
        if "@" not in raw_email or "." not in raw_email:
            return _json_error("Invalid email address", 400)

        # Unique check (excluding self)
        existing = db.session.scalars(
            select(User).where(User.email == raw_email, User.id != user.id)
        ).first()
        if existing is not None:
            return _json_error("Email already in use", 409)

        user.email = raw_email  # ✅ always str (Pyright-clean)

    # ----------------------------
    # Location (nullable)
    # ----------------------------
    if "location" in data:
        user.location = str(data.get("location") or "").strip() or None

    # ----------------------------
    # Optional: allow enabling/disabling accounts
    # Remove if you only want admins to do this elsewhere.
    # ----------------------------
    if "is_active" in data:
        user.is_active = bool(data.get("is_active"))

    # ----------------------------
    # Audit timestamp (naive UTC)
    # ----------------------------
    user.updated_at = datetime.utcnow()

    db.session.commit()
    return _json_ok({"message": "Profile updated", "user": user.to_dict()}, 200)
