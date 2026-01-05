# =============================================================================
# backend/routes/auth.py — Auth API (Register/Login/Refresh) (PYRIGHT-SAFE)
# =============================================================================
# FILE ROLE:
#   • Authentication boundary for AgroConnect Namibia backend.
#   • POST /register, POST /login, POST /refresh
#
# IMPORTANT:
#   The login 500 you saw was not from this route logic — it was ORM mapper
#   configuration crashing (User.farmer_profile + Rating.customer_id issues).
#   With the updated models above, login should stop 500-ing.
# =============================================================================

from __future__ import annotations

import uuid
from typing import Any, Optional, TypedDict, cast

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from backend.database.db import db
from backend.extensions import bcrypt
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User
from backend.utils.jwt_utils import jwt_decode, jwt_encode
from backend.utils.validators import validate_phone as _validate_phone

auth_bp = Blueprint("auth", __name__)


class RegisterJSON(TypedDict, total=False):
    full_name: str
    phone: str
    email: str
    location: str
    password: str
    role: int


class LoginJSON(TypedDict, total=False):
    phone: str
    email: str
    identifier: str
    password: str


def api_response(success: bool, message: str, status: int = 200, **data: Any) -> Response:
    resp = cast(Response, jsonify({"success": success, "message": message, **data}))
    resp.status_code = status
    return resp


def validate_phone_str(raw: Any) -> str:
    phone = _validate_phone(raw)
    if not phone:
        raise ValueError("Valid phone number is required")
    return phone


def _normalize_identifier(value: Any) -> str:
    return str(value or "").strip()


def _looks_like_email(value: str) -> bool:
    v = value.strip()
    return ("@" in v) and ("." in v)


def _validate_email_required(raw: Any) -> str:
    email = str(raw or "").strip().lower()
    if not email:
        raise ValueError("Email is required")
    if "@" not in email or "." not in email:
        raise ValueError("Valid email is required")
    return email


def _hash_to_db_string(pw_hash: Any) -> str:
    if pw_hash is None:
        return ""
    if isinstance(pw_hash, (bytes, bytearray)):
        try:
            return bytes(pw_hash).decode("utf-8")
        except Exception:
            return ""
    return str(pw_hash)


def _issue_tokens(user: User) -> dict[str, str]:
    access = jwt_encode({"sub": str(user.id)}, purpose="access", hours=1)
    refresh = jwt_encode({"sub": str(user.id)}, purpose="refresh", hours=24 * 30)
    return {"accessToken": access, "refreshToken": refresh, "token": access}


@auth_bp.post("/register")
def register() -> Response:
    data = cast(RegisterJSON, request.get_json(silent=True) or {})

    full_name = str(data.get("full_name") or "").strip()
    password = str(data.get("password") or "")
    location_raw = str(data.get("location") or "").strip()
    role = int(data.get("role") or ROLE_FARMER)

    if not full_name:
        return api_response(False, "Full name is required", 400)

    if len(password.strip()) < 6:
        return api_response(False, "Password must be at least 6 characters", 400)

    if role not in (ROLE_ADMIN, ROLE_FARMER, ROLE_CUSTOMER):
        return api_response(False, "Invalid role", 400)

    try:
        phone = validate_phone_str(data.get("phone"))
    except ValueError as exc:
        return api_response(False, str(exc), 400)

    try:
        email = _validate_email_required(data.get("email"))
    except ValueError as exc:
        return api_response(False, str(exc), 400)

    location: Optional[str] = location_raw or None

    if db.session.scalars(select(User).where(User.phone == phone)).first():
        return api_response(False, "Phone already registered", 409)
    if db.session.scalars(select(User).where(User.email == email)).first():
        return api_response(False, "Email already registered", 409)

    user = User()
    user.full_name = full_name
    user.phone = phone
    user.email = email
    user.location = location
    user.role = role
    user.is_active = True

    try:
        raw_hash = bcrypt.generate_password_hash(password)
    except Exception:
        return api_response(False, "Password hashing failed (bcrypt backend unavailable)", 500)

    pw_hash = _hash_to_db_string(raw_hash)
    if not pw_hash or pw_hash.strip().lower() == "none":
        return api_response(False, "Password hashing failed (invalid hash output)", 500)

    user.password_hash = pw_hash

    try:
        db.session.add(user)
        db.session.commit()
        db.session.refresh(user)
    except IntegrityError:
        db.session.rollback()
        return api_response(False, "Phone or email already registered", 409)
    except Exception:
        db.session.rollback()
        return api_response(False, "Registration failed", 500)

    return api_response(True, "Registration successful", 201, user=user.to_dict(), **_issue_tokens(user))


@auth_bp.post("/login")
def login() -> Response:
    data = cast(LoginJSON, request.get_json(silent=True) or {})
    password = str(data.get("password") or "").strip()

    if not password:
        return api_response(False, "Invalid login credentials", 401)

    user: Optional[User] = None

    email = str(data.get("email") or "").strip().lower()
    phone_raw: Any = data.get("phone")
    identifier = _normalize_identifier(data.get("identifier"))

    if identifier and not (email or phone_raw):
        if _looks_like_email(identifier):
            email = identifier.strip().lower()
        else:
            phone_raw = identifier

    if phone_raw:
        try:
            phone = validate_phone_str(phone_raw)
            user = db.session.scalars(select(User).where(User.phone == phone)).first()
        except ValueError:
            user = None

    if not user and email:
        user = db.session.scalars(select(User).where(User.email == email)).first()

    if not user or not getattr(user, "is_active", True):
        return api_response(False, "Invalid login credentials", 401)

    ph = getattr(user, "password_hash", None)
    if not isinstance(ph, str) or not ph:
        return api_response(False, "Invalid login credentials", 401)

    try:
        ok = bool(bcrypt.check_password_hash(ph, password))
    except Exception:
        ok = False

    if not ok:
        return api_response(False, "Invalid login credentials", 401)

    return api_response(True, "Login successful", 200, user=user.to_dict(), **_issue_tokens(user))


@auth_bp.post("/refresh")
def refresh() -> Response:
    payload = cast(dict[str, Any], request.get_json(silent=True) or {})
    token = payload.get("refreshToken")

    if not isinstance(token, str) or not token.strip():
        return api_response(False, "Refresh token required", 400)

    try:
        decoded = jwt_decode(token)
    except Exception:
        return api_response(False, "Invalid refresh token", 401)

    if decoded.get("purpose") != "refresh":
        return api_response(False, "Invalid refresh token", 401)

    sub = decoded.get("sub")
    if not isinstance(sub, str) or not sub:
        return api_response(False, "Invalid refresh token", 401)

    try:
        user_id = uuid.UUID(sub)
    except Exception:
        return api_response(False, "Invalid refresh token", 401)

    user = db.session.get(User, user_id)
    if not user:
        return api_response(False, "User not found", 404)
    if not getattr(user, "is_active", True):
        return api_response(False, "Account disabled", 403)

    return api_response(True, "Token refreshed", 200, **_issue_tokens(user))
