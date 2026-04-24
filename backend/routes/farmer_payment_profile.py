# ============================================================================
# backend/routes/farmer_payment_profile.py — Farmer EFT / Bank Profile API
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Farmer-only endpoints for managing EFT / bank details.
#
# ROUTES:
#   GET /api/farmers/payment-profile/me
#   GET /api/farmers/payment-profile
#   PUT /api/farmers/payment-profile/me
#   PUT /api/farmers/payment-profile
#
# THIS UPDATE:
#   ✅ Fixes Pyright/Pylance issues:
#        - no direct FarmerPaymentProfile.__table__ access
#        - no direct current_app.logger access
#   ✅ Auto-creates the farmer_payment_profiles table in dev if it is missing
#   ✅ Keeps one payment profile per farmer
#   ✅ Makes GET and PUT resilient when the migration was not applied yet
#   ✅ Improves farmer_id parsing from authenticated context
#   ✅ Updates updated_at explicitly on save
#   ✅ Returns clearer backend errors
#
# IMPORTANT:
#   This file is dev-friendly. In production, you should still apply a proper
#   Alembic migration for farmer_payment_profiles.
# ============================================================================

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional, cast
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import Table, inspect as sa_inspect
from sqlalchemy.exc import SQLAlchemyError

from backend.database.db import db
from backend.models.farmer_payment_profile import FarmerPaymentProfile
from backend.models.user import ROLE_ADMIN, User
from backend.utils.require_auth import require_access_token

farmer_payment_profile_bp = Blueprint("farmer_payment_profile", __name__)

# -----------------------------------------------------------------------------
# Module logger
# -----------------------------------------------------------------------------
# NOTE:
#   Using a plain Python logger avoids the Pyright issue on current_app.logger.
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------
# NOTE:
#   Keep the table name explicit so we do not depend on typed access to
#   SQLAlchemy declarative internals such as __table__.
FARMER_PAYMENT_PROFILE_TABLE = "farmer_payment_profiles"


# -----------------------------------------------------------------------------
# Small helpers
# -----------------------------------------------------------------------------
def _safe_str(v: Any) -> Optional[str]:
    """Return a trimmed string or None."""
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _as_uuid(v: Any) -> Optional[UUID]:
    """Best-effort UUID parser."""
    if v is None:
        return None
    if isinstance(v, UUID):
        return v

    s = _safe_str(v)
    if not s:
        return None

    try:
        return UUID(s)
    except Exception:
        return None


def _is_truthy(v: Any) -> bool:
    """Best-effort bool parser for JSON/query/body values."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0

    s = (_safe_str(v) or "").lower()
    return s in {"1", "true", "yes", "y", "on"}


def _user_id(user: User) -> Optional[UUID]:
    """
    Resolve the authenticated user's UUID safely.

    WHY:
      Different auth flows may attach:
        - id
        - user_id
        - userId
        - sub
    """
    return (
        _as_uuid(getattr(user, "id", None))
        or _as_uuid(getattr(user, "user_id", None))
        or _as_uuid(getattr(user, "userId", None))
        or _as_uuid(getattr(user, "sub", None))
    )


def _is_admin(user: User) -> bool:
    """Support both numeric role and optional role-name variants."""
    raw_role = getattr(user, "role", None)
    role_name = _safe_str(getattr(user, "role_name", None) or getattr(user, "roleName", None))

    try:
        if raw_role is not None and int(raw_role) == int(ROLE_ADMIN):
            return True
    except Exception:
        pass

    return (role_name or _safe_str(raw_role) or "").lower() == "admin"


def _is_farmer(user: User) -> bool:
    """Support both numeric role and optional role-name variants."""
    raw_role = getattr(user, "role", None)
    role_name = _safe_str(getattr(user, "role_name", None) or getattr(user, "roleName", None))

    try:
        if raw_role is not None and int(raw_role) == 2:
            return True
    except Exception:
        pass

    return (role_name or _safe_str(raw_role) or "").lower() == "farmer"


def _serialize(profile: Optional[FarmerPaymentProfile], farmer_id: UUID) -> dict[str, object]:
    """
    Return a stable API shape even when the farmer has never saved a profile.
    """
    if profile is None:
        return {
            "profile_id": None,
            "farmer_id": str(farmer_id),
            "bank_name": "",
            "account_name": "",
            "account_number": "",
            "branch_code": "",
            "payment_instructions": "",
            "use_for_eft": True,
            "is_active": True,
            "is_complete": False,
        }

    return profile.to_dict()


# -----------------------------------------------------------------------------
# Table readiness
# -----------------------------------------------------------------------------
def _resolve_profile_table() -> Optional[Table]:
    """
    Resolve the mapped SQLAlchemy Table object in a Pyright-safe way.

    WHY THIS EXISTS:
      Direct access like FarmerPaymentProfile.__table__ can work at runtime,
      but static type checkers often flag it as unknown on declarative classes.

    STRATEGY:
      1) Ask the model metadata for the registered table by name
      2) Fallback to db.Model.metadata in case project metadata is centralized
    """
    # First preference: metadata attached to the model class
    model_metadata = getattr(FarmerPaymentProfile, "metadata", None)
    if model_metadata is not None:
        tables = getattr(model_metadata, "tables", None)
        if isinstance(tables, dict):
            found = tables.get(FARMER_PAYMENT_PROFILE_TABLE)
            if isinstance(found, Table):
                return found

    # Fallback: global SQLAlchemy metadata used by the project
    base_metadata = getattr(db.Model, "metadata", None)
    if base_metadata is not None:
        tables = getattr(base_metadata, "tables", None)
        if isinstance(tables, dict):
            found = tables.get(FARMER_PAYMENT_PROFILE_TABLE)
            if isinstance(found, Table):
                return found

    return None


def _ensure_profile_table() -> tuple[bool, Optional[str]]:
    """
    Ensure the farmer_payment_profiles table exists.

    WHY:
      The model may exist in code while the DB table is still missing in dev.

    IMPORTANT:
      This is development resilience only. Production should still use a proper
      database migration.
    """
    try:
        bind = db.session.get_bind() or db.engine
        inspector = sa_inspect(bind)

        if inspector.has_table(FARMER_PAYMENT_PROFILE_TABLE):
            return True, None

        table = _resolve_profile_table()
        if table is None:
            return (
                False,
                "farmer_payment_profiles table metadata is not registered. "
                "Check that FarmerPaymentProfile is imported correctly.",
            )

        table.create(bind=bind, checkfirst=True)
        return True, None

    except Exception as exc:
        db.session.rollback()
        logger.exception("Failed to ensure farmer_payment_profiles table exists")
        return False, str(exc)


def _get_profile(farmer_id: UUID) -> Optional[FarmerPaymentProfile]:
    """
    Best-effort lookup for a farmer profile.
    """
    try:
        return (
            db.session.query(FarmerPaymentProfile)
            .filter(FarmerPaymentProfile.farmer_id == farmer_id)
            .one_or_none()
        )
    except Exception:
        db.session.rollback()
        logger.exception("Failed to query farmer EFT profile for farmer_id=%s", farmer_id)
        return None


# -----------------------------------------------------------------------------
# Auth wrapper
# -----------------------------------------------------------------------------
def token_required(fn):
    @require_access_token
    def wrapper(*args, **kwargs):
        user = getattr(request, "current_user", None)
        if not isinstance(user, User):
            return jsonify({"ok": False, "message": "Unauthorized"}), 401
        return fn(cast(User, user), *args, **kwargs)

    wrapper.__name__ = getattr(fn, "__name__", "wrapped_farmer_payment_profile")
    return wrapper


# -----------------------------------------------------------------------------
# Read current farmer payment profile
# -----------------------------------------------------------------------------
@farmer_payment_profile_bp.get("/payment-profile")
@farmer_payment_profile_bp.get("/payment-profile/me")
@token_required
def get_my_farmer_payment_profile(current_user: User):
    """
    Return the authenticated farmer's current EFT profile.

    Response remains stable even when the farmer has never saved details before.
    """
    if not (_is_farmer(current_user) or _is_admin(current_user)):
        return jsonify({"ok": False, "message": "Forbidden"}), 403

    farmer_id = _user_id(current_user)
    if farmer_id is None:
        return jsonify({"ok": False, "message": "Invalid authenticated farmer context"}), 401

    ready, reason = _ensure_profile_table()
    if not ready:
        return jsonify(
            {
                "ok": False,
                "message": "Failed to prepare farmer EFT storage.",
                "details": reason,
            }
        ), 500

    profile = _get_profile(farmer_id)
    return jsonify({"ok": True, "data": _serialize(profile, farmer_id)}), 200


# -----------------------------------------------------------------------------
# Create or update current farmer payment profile
# -----------------------------------------------------------------------------
@farmer_payment_profile_bp.put("/payment-profile")
@farmer_payment_profile_bp.put("/payment-profile/me")
@token_required
def upsert_my_farmer_payment_profile(current_user: User):
    """
    Create or update the authenticated farmer's EFT profile.
    """
    if not (_is_farmer(current_user) or _is_admin(current_user)):
        return jsonify({"ok": False, "message": "Forbidden"}), 403

    farmer_id = _user_id(current_user)
    if farmer_id is None:
        return jsonify({"ok": False, "message": "Invalid authenticated farmer context"}), 401

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        payload = {}

    bank_name = _safe_str(payload.get("bank_name")) or None
    account_name = _safe_str(payload.get("account_name")) or None
    account_number = _safe_str(payload.get("account_number")) or None
    branch_code = _safe_str(payload.get("branch_code")) or None
    payment_instructions = _safe_str(payload.get("payment_instructions")) or None
    use_for_eft = _is_truthy(payload.get("use_for_eft")) if "use_for_eft" in payload else True
    is_active = _is_truthy(payload.get("is_active")) if "is_active" in payload else True

    # -------------------------------------------------------------------------
    # Validation
    # -------------------------------------------------------------------------
    # These are the core details customers need to complete an EFT payment.
    if use_for_eft and (not bank_name or not account_name or not account_number):
        return jsonify(
            {
                "ok": False,
                "message": "bank_name, account_name, and account_number are required when EFT is enabled.",
            }
        ), 400

    ready, reason = _ensure_profile_table()
    if not ready:
        return jsonify(
            {
                "ok": False,
                "message": "Failed to prepare farmer EFT storage.",
                "details": reason,
            }
        ), 500

    try:
        profile = (
            db.session.query(FarmerPaymentProfile)
            .filter(FarmerPaymentProfile.farmer_id == farmer_id)
            .one_or_none()
        )

        now = datetime.utcnow()

        if profile is None:
            profile = FarmerPaymentProfile()
            profile.farmer_id = farmer_id

            # Helpful in dev when DB defaults/triggers are not yet in place.
            if hasattr(profile, "created_at"):
                profile.created_at = now

            db.session.add(profile)

        # ---------------------------------------------------------------------
        # Persist latest EFT profile values
        # ---------------------------------------------------------------------
        profile.bank_name = bank_name
        profile.account_name = account_name
        profile.account_number = account_number
        profile.branch_code = branch_code
        profile.payment_instructions = payment_instructions
        profile.use_for_eft = bool(use_for_eft)
        profile.is_active = bool(is_active)

        if hasattr(profile, "updated_at"):
            profile.updated_at = now

        db.session.commit()
        db.session.refresh(profile)

        return jsonify(
            {
                "ok": True,
                "message": "Farmer EFT details saved successfully",
                "data": profile.to_dict(),
            }
        ), 200

    except SQLAlchemyError as exc:
        db.session.rollback()
        logger.exception("Failed to save farmer EFT details for farmer_id=%s", farmer_id)

        return jsonify(
            {
                "ok": False,
                "message": "Failed to save farmer EFT details.",
                "details": str(exc),
            }
        ), 500