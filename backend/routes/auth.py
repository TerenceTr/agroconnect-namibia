# =============================================================================
# backend/routes/auth.py — Auth API (Register/Login/Refresh/Logout)
# -----------------------------------------------------------------------------
# FILE ROLE:
#   Authentication boundary for AgroConnect Namibia backend.
#
# ROUTES:
#   POST /register
#   POST /login
#   POST /refresh
#   POST /logout
#   POST /logout-all
#   GET  /me
#   PATCH/PUT /me
#
# UPDATED DESIGN:
#   ✅ login_events now stores AUTH / SESSION events only
#   ✅ "seen" / heartbeat activity must NOT be written into login_events
#   ✅ login/logout/refresh/logout-all now use the centralized AuditLogger
#   ✅ users.last_login_at + users.last_seen_at are updated directly when present
#   ✅ /me and /me update now write USER ACTIVITY events (not auth events)
#   ✅ explicit logout still removes the user from live presence immediately
#
# IMPORTANT ARCHITECTURE RULE:
#   - login_events           => auth/session history only
#   - user_activity_events   => what user did after login
#   - admin_audit_log        => privileged admin actions
#
# KEY FIX IN THIS VERSION:
#   ✅ Imports Werkzeug password checker for legacy hash compatibility
# =============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional, TypedDict, cast

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import func, inspect, select, text
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash as werkzeug_check_password_hash

from backend.database.db import db
from backend.extensions import bcrypt
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User
from backend.services.audit_logger import AuditLogger
from backend.services.token_service import (
    issue_token_pair,
    revoke_all_user_refresh_tokens,
    revoke_refresh_token,
    rotate_refresh_token,
    validate_refresh_token,
)
from backend.utils.require_auth import require_access_token
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


class RefreshJSON(TypedDict, total=False):
    refreshToken: str


def api_response(success: bool, message: str, status: int = 200, **data: Any) -> Response:
    resp = cast(Response, jsonify({"success": success, "message": message, **data}))
    resp.status_code = status
    return resp


# -----------------------------------------------------------------------------
# Phone normalization policy
# -----------------------------------------------------------------------------
# DESIGN DECISION:
#   • users.phone stores the Namibian LOCAL display form: 081xxxxxxx
#   • USSD / SMS channels may use the provider-friendly E.164 form: +26481xxxxxxx
#
# WHY THIS EXISTS:
#   The web interface, profile APIs, and ordinary user records should remain
#   human-friendly and consistent inside `users.phone`, while USSD credentials
#   can keep the channel-native international form. To make that safe, auth
#   accepts either 081... or +264... input and normalizes it to the local form
#   before touching the `users` table.
# -----------------------------------------------------------------------------
def _phone_digits(raw: Any) -> str:
    return "".join(ch for ch in str(raw or "") if ch.isdigit())


def _phone_to_local(raw: Any) -> Optional[str]:
    """
    Convert supported Namibia phone inputs to the local `081...` form used by
    `users.phone`.

    Accepted examples:
      • 0812345678
      • +264812345678
      • 264812345678
    """
    digits = _phone_digits(raw)
    if not digits:
        return None

    candidate: Optional[str] = None
    if len(digits) == 10 and digits.startswith(("081", "083", "085")):
        candidate = digits
    elif len(digits) == 12 and digits.startswith(("26481", "26483", "26485")):
        candidate = f"0{digits[3:]}"

    if not candidate:
        return None

    phone = _validate_phone(candidate)
    if not phone:
        return None
    return phone


def _phone_to_e164(raw: Any) -> Optional[str]:
    local = _phone_to_local(raw)
    if not local:
        return None
    return f"+264{local[1:]}"


def _phone_to_key(raw: Any) -> Optional[str]:
    e164 = _phone_to_e164(raw)
    return _phone_digits(e164) if e164 else None


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        text_value = str(value).strip()
    except Exception:
        return None
    return text_value or None


def _user_phone_candidates(raw: Any) -> list[str]:
    """
    Candidate values for lookups / uniqueness checks.

    This keeps auth compatible with any legacy rows that may still contain a
    non-local representation while new writes are standardized to `081...`.
    """
    local = _phone_to_local(raw)
    e164 = _phone_to_e164(raw)
    key = _phone_to_key(raw)

    values: list[str] = []
    for candidate in (raw, local, e164, key, f"+{key}" if key else None):
        text_value = _safe_str(candidate)
        if text_value and text_value not in values:
            values.append(text_value)
    return values


def validate_phone_str(raw: Any) -> str:
    phone = _phone_to_local(raw)
    if not phone:
        raise ValueError("Valid phone number is required")
    return phone


def _find_user_by_phone_value(raw: Any) -> Optional[User]:
    candidates = _user_phone_candidates(raw)
    if not candidates:
        return None
    return db.session.scalars(select(User).where(User.phone.in_(candidates))).first()


def _phone_conflict_exists(raw: Any, *, exclude_user_id: Optional[uuid.UUID] = None) -> bool:
    candidates = _user_phone_candidates(raw)
    if not candidates:
        return False

    stmt = select(User).where(User.phone.in_(candidates))
    if exclude_user_id is not None:
        stmt = stmt.where(User.id != exclude_user_id)
    return db.session.scalars(stmt).first() is not None


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


def _password_matches(stored_hash: Any, candidate_password: Any) -> bool:
    """
    Check a candidate password against the stored hash using a tolerant strategy.

    WHY THIS EXISTS:
      • Some environments return bcrypt hashes as strings, others as bytes.
      • Some older rows may have been generated by Werkzeug instead of bcrypt.
      • Login should NOT strip the user's password because leading/trailing spaces
        are part of the secret if the account was created that way.

    POLICY:
      1. Try Flask-Bcrypt / bcrypt wrapper first (current standard)
      2. Fallback to Werkzeug hash checking for legacy compatibility
      3. Never raise from auth verification
    """
    raw_hash = _safe_str(stored_hash)
    if not raw_hash:
        return False

    password = str(candidate_password or "")
    if not password:
        return False

    try:
        if bool(bcrypt.check_password_hash(raw_hash, password)):
            return True
    except Exception:
        pass

    try:
        if raw_hash.startswith(("pbkdf2:", "scrypt:", "argon2:")):
            return bool(werkzeug_check_password_hash(raw_hash, password))
    except Exception:
        pass

    return False


def _user_uuid(user: User) -> Optional[uuid.UUID]:
    raw = getattr(user, "id", None) or getattr(user, "user_id", None)
    if raw is None:
        return None
    if isinstance(raw, uuid.UUID):
        return raw
    try:
        return uuid.UUID(str(raw))
    except Exception:
        return None


_AUTH_CAPS: dict[str, Optional[bool]] = {
    "users_last_seen_at": None,
    "users_last_login_at": None,
}


def _has_users_column(column_name: str) -> bool:
    cache_key = f"users_{column_name}"
    cached = _AUTH_CAPS.get(cache_key)
    if isinstance(cached, bool):
        return cached
    try:
        cols = inspect(db.engine).get_columns("users")
        ok = any((c.get("name") == column_name) for c in (cols or []))
    except Exception:
        ok = False
    _AUTH_CAPS[cache_key] = ok
    return ok


def _client_ip() -> Optional[str]:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()[:64] or None
    return request.remote_addr or None


def _user_agent() -> Optional[str]:
    ua = request.headers.get("User-Agent")
    return ua[:256] if ua else None


def _request_session_id() -> Optional[str]:
    """
    Best-effort session correlation ID from headers/body.
    """
    header_value = (
        request.headers.get("X-Session-ID")
        or request.headers.get("X-Client-Session")
        or request.headers.get("X-Device-Session")
    )
    if header_value:
        return str(header_value).strip()[:128] or None

    payload = request.get_json(silent=True) or {}
    if isinstance(payload, dict):
        raw = payload.get("sessionId") or payload.get("session_id")
        if raw is not None:
            return str(raw).strip()[:128] or None

    return None


def _mark_user_online(user_id: str) -> None:
    try:
        from backend.utils.presence import mark_active

        mark_active(user_id)
    except Exception:
        pass

    try:
        from backend.services.presence_store import touch

        touch(user_id)
    except Exception:
        pass


def _mark_user_offline(user_id: str) -> None:
    try:
        from backend.utils.presence import mark_offline

        mark_offline(user_id)
    except Exception:
        pass

    try:
        from backend.services.presence_store import mark_offline as mark_offline_memory

        mark_offline_memory(user_id)
    except Exception:
        pass


def _touch_user_auth_timestamps(
    *,
    user_id: uuid.UUID,
    update_login: bool = False,
) -> None:
    """
    Queue best-effort timestamp updates inside the CURRENT ORM transaction.

    This reduces extra auth round-trips by letting login / refresh / logout
    persist token changes, timestamp updates, and auth audit entries with a
    single commit where possible.
    """
    now = datetime.utcnow()

    try:
        if _has_users_column("last_seen_at"):
            db.session.execute(
                text("UPDATE users SET last_seen_at = :ts WHERE id = :uid"),
                {"ts": now, "uid": str(user_id)},
            )

        if update_login and _has_users_column("last_login_at"):
            db.session.execute(
                text("UPDATE users SET last_login_at = :ts WHERE id = :uid"),
                {"ts": now, "uid": str(user_id)},
            )
    except Exception:
        return


@auth_bp.get("/me")
@require_access_token
def auth_me() -> Response:
    """
    Canonical authenticated profile endpoint.
    """
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return api_response(False, "Unauthorized", 401)

    current_user_id = _user_uuid(current_user)
    payload = current_user.to_dict()

    if current_user_id is not None:
        AuditLogger.log_user_activity(
            user_id=current_user_id,
            role_name=getattr(current_user, "role", None),
            action="view_profile",
            target_type="profile",
            target_id=current_user_id,
            session_id=_request_session_id(),
            route=request.path,
            http_method=request.method,
            ip_address=_client_ip(),
            user_agent=_user_agent(),
            metadata_json={"source": "auth_me"},
        )

    return api_response(True, "Profile loaded", 200, data=payload, user=payload)


@auth_bp.patch("/me")
@auth_bp.put("/me")
@require_access_token
def auth_update_me() -> Response:
    """
    Canonical self-profile update endpoint.
    Allowed fields:
      • full_name
      • phone
      • email
      • location
    """
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return api_response(False, "Unauthorized", 401)

    current_user_id = _user_uuid(current_user)
    if current_user_id is None:
        return api_response(False, "Invalid authenticated user context", 401)

    payload = cast(dict[str, Any], request.get_json(silent=True) or {})
    if not isinstance(payload, dict):
        payload = {}

    changed = False
    changed_fields: list[str] = []

    if "full_name" in payload:
        name = str(payload.get("full_name") or "").strip()
        if not name:
            return api_response(False, "Full name is required", 400)
        current_user.full_name = name
        changed = True
        changed_fields.append("full_name")

    if "phone" in payload:
        try:
            phone = validate_phone_str(payload.get("phone"))
        except ValueError as exc:
            return api_response(False, str(exc), 400)

        if _phone_conflict_exists(phone, exclude_user_id=current_user_id):
            return api_response(False, "Phone already in use", 409)

        current_user.phone = phone
        changed = True
        changed_fields.append("phone")

    if "email" in payload:
        try:
            email = _validate_email_required(payload.get("email"))
        except ValueError as exc:
            return api_response(False, str(exc), 400)

        existing = db.session.scalars(
            select(User).where(func.lower(func.trim(User.email)) == email, User.id != current_user_id)
        ).first()
        if existing:
            return api_response(False, "Email already in use", 409)

        current_user.email = email
        changed = True
        changed_fields.append("email")

    if "location" in payload:
        location_raw = str(payload.get("location") or "").strip()
        current_user.location = location_raw or None
        changed = True
        changed_fields.append("location")

    if not changed:
        user_payload = current_user.to_dict()
        return api_response(True, "No changes", 200, data=user_payload, user=user_payload)

    try:
        db.session.add(current_user)
        db.session.commit()
        db.session.refresh(current_user)
    except IntegrityError:
        db.session.rollback()
        return api_response(False, "Phone or email already registered", 409)
    except Exception:
        db.session.rollback()
        return api_response(False, "Profile update failed", 500)

    user_payload = current_user.to_dict()

    AuditLogger.log_user_activity(
        user_id=current_user_id,
        role_name=getattr(current_user, "role", None),
        action="update_profile",
        target_type="profile",
        target_id=current_user_id,
        session_id=_request_session_id(),
        route=request.path,
        http_method=request.method,
        ip_address=_client_ip(),
        user_agent=_user_agent(),
        metadata_json={"changed_fields": changed_fields},
    )

    return api_response(True, "Profile updated", 200, data=user_payload, user=user_payload)


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

    if _phone_conflict_exists(phone):
        return api_response(False, "Phone already registered", 409)

    if db.session.scalars(select(User).where(func.lower(func.trim(User.email)) == email)).first():
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
        db.session.flush()

        tokens = issue_token_pair(user, refresh_days=30, commit=False)

        db.session.commit()
        db.session.refresh(user)

    except IntegrityError:
        db.session.rollback()
        return api_response(False, "Phone or email already registered", 409)
    except Exception:
        db.session.rollback()
        return api_response(False, "Registration failed", 500)

    user_uuid = _user_uuid(user)
    if user_uuid is not None:
        AuditLogger.log_user_activity(
            user_id=user_uuid,
            role_name=getattr(user, "role", None),
            action="register_account",
            target_type="user",
            target_id=user_uuid,
            session_id=_request_session_id(),
            route=request.path,
            http_method=request.method,
            ip_address=_client_ip(),
            user_agent=_user_agent(),
            metadata_json={"registration_role": user.to_dict().get("role_name")},
        )

    return api_response(
        True,
        "Registration successful",
        201,
        user=user.to_dict(),
        **tokens,
    )


@auth_bp.post("/login")
def login() -> Response:
    data = cast(LoginJSON, request.get_json(silent=True) or {})
    password = str(data.get("password") or "")

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
            validate_phone_str(phone_raw)
            user = _find_user_by_phone_value(phone_raw)
        except ValueError:
            user = None

    if not user and email:
        user = db.session.scalars(
            select(User).where(func.lower(func.trim(User.email)) == email)
        ).first()

    if not user or not getattr(user, "is_active", True):
        return api_response(False, "Invalid login credentials", 401)

    ph = getattr(user, "password_hash", None)
    if not isinstance(ph, str) or not ph:
        return api_response(False, "Invalid login credentials", 401)

    ok = _password_matches(ph, password)

    if not ok:
        uid = _user_uuid(user)
        if uid is not None:
            AuditLogger.log_failed_login(
                user_id=uid,
                ip_address=_client_ip(),
                user_agent=_user_agent(),
            )
        return api_response(False, "Invalid login credentials", 401)

    uid = _user_uuid(user)

    try:
        tokens = issue_token_pair(user, refresh_days=30, commit=False)

        if uid is not None:
            _touch_user_auth_timestamps(user_id=uid, update_login=True)
            AuditLogger.log_login(
                user_id=uid,
                ip_address=_client_ip(),
                user_agent=_user_agent(),
                commit=False,
            )

        db.session.commit()
    except Exception:
        db.session.rollback()
        return api_response(False, "Login failed", 500)

    if uid is not None:
        try:
            _mark_user_online(str(uid))
        except Exception:
            pass

    return api_response(
        True,
        "Login successful",
        200,
        user=user.to_dict(),
        **tokens,
    )


@auth_bp.post("/refresh")
def refresh() -> Response:
    payload = cast(RefreshJSON, request.get_json(silent=True) or {})
    raw_token = payload.get("refreshToken")

    if not isinstance(raw_token, str) or not raw_token.strip():
        return api_response(False, "Refresh token required", 400)

    try:
        rotated = rotate_refresh_token(raw_token, refresh_days=30, commit=False)
        if rotated is None:
            db.session.rollback()
            return api_response(False, "Invalid refresh token", 401)

        user, tokens = rotated
        uid = _user_uuid(user)

        if uid is not None:
            _touch_user_auth_timestamps(user_id=uid, update_login=False)
            AuditLogger.log_session_refresh(
                user_id=uid,
                ip_address=_client_ip(),
                user_agent=_user_agent(),
                commit=False,
            )

        db.session.commit()
    except Exception:
        db.session.rollback()
        return api_response(False, "Token refresh failed", 500)

    if uid is not None:
        try:
            _mark_user_online(str(uid))
        except Exception:
            pass

    return api_response(
        True,
        "Token refreshed",
        200,
        user=user.to_dict(),
        **tokens,
    )


@auth_bp.post("/logout")
def logout() -> Response:
    payload = cast(RefreshJSON, request.get_json(silent=True) or {})
    raw_token = payload.get("refreshToken")

    if not isinstance(raw_token, str) or not raw_token.strip():
        return api_response(False, "Refresh token required", 400)

    validated = validate_refresh_token(raw_token)
    if validated is None:
        return api_response(False, "Invalid refresh token", 401)

    user, _record = validated
    uid = _user_uuid(user)

    try:
        ok = revoke_refresh_token(raw_token, commit=False)
        if not ok:
            db.session.rollback()
            return api_response(False, "Invalid refresh token", 401)

        if uid is not None:
            _touch_user_auth_timestamps(user_id=uid, update_login=False)
            AuditLogger.log_logout(
                user_id=uid,
                ip_address=_client_ip(),
                user_agent=_user_agent(),
                commit=False,
            )

        db.session.commit()
    except Exception:
        db.session.rollback()
        return api_response(False, "Logout failed", 500)

    if uid is not None:
        try:
            _mark_user_offline(str(uid))
        except Exception:
            pass

    return api_response(True, "Logout successful", 200)


@auth_bp.post("/logout-all")
@require_access_token
def logout_all() -> Response:
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return api_response(False, "Unauthorized", 401)

    uid = _user_uuid(current_user)
    if uid is None:
        return api_response(False, "Invalid authenticated user context", 401)

    try:
        revoked = revoke_all_user_refresh_tokens(uid, commit=False)
        _touch_user_auth_timestamps(user_id=uid, update_login=False)
        AuditLogger.log_logout_all(
            user_id=uid,
            ip_address=_client_ip(),
            user_agent=_user_agent(),
            commit=False,
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        return api_response(False, "Logout-all failed", 500)

    try:
        _mark_user_offline(str(uid))
    except Exception:
        pass

    return api_response(
        True,
        "All refresh sessions revoked",
        200,
        revoked=revoked,
    )