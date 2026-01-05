# ============================================================================
# backend/utils/require_auth.py — JWT Access Guard (Single Source of Truth)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Single source of truth for verifying JWT access tokens.
#
# WHAT THIS PROVIDES:
#   • AuthError                    -> typed exception used by wrappers/middleware
#   • verify_access_from_request() -> verifies JWT and injects request user fields
#   • require_access_token         -> decorator for protecting routes
#   • require_auth(*roles)         -> decorator for protecting routes + role gate
#
# INJECTS (compat + convenience):
#   • request.user_id      -> uuid.UUID
#   • request.user_id_str  -> str
#   • request.current_user -> User
#   • g.current_user       -> User (best-effort)
#
# NOTE ON ROLES:
#   DB stores role as INT (1/2/3) but User exposes role_name/is_admin helpers.
#   Role checks should be against role_name ("admin"|"farmer"|"customer").
# ============================================================================

from __future__ import annotations

import uuid
from functools import wraps
from typing import Any, Callable, Optional, ParamSpec, TypeVar, cast

from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Request, Response

from backend.database.db import db
from backend.models.user import User
from backend.utils.jwt_utils import jwt_decode

P = ParamSpec("P")
R = TypeVar("R")


# ----------------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------------
class AuthError(Exception):
    """
    Raised when a request is not authorized.
    Middleware/wrappers can catch this and return a JSON 401/403.
    """

    def __init__(self, message: str = "Unauthorized", status_code: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self) -> str:
        return self.message


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def _to_uuid(value: Any) -> Optional[uuid.UUID]:
    """Convert any token user identifier into a UUID, if possible."""
    if value is None:
        return None
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _role_name(user: User) -> str:
    """
    Normalize role to a name string.

    Prefers:
      • user.role_name (your model property)

    Falls back to:
      • mapping role int -> name
    """
    rn = getattr(user, "role_name", None)
    if isinstance(rn, str) and rn.strip():
        return rn.strip().lower()

    # Fallback: role is int-ish (1/2/3). IMPORTANT: guard against None.
    role_raw = getattr(user, "role", None)
    if role_raw is None:
        role_int = 3
    else:
        try:
            role_int = int(role_raw)
        except Exception:
            role_int = 3

    return {1: "admin", 2: "farmer", 3: "customer"}.get(role_int, "customer")


def _json_error(message: str, status: int) -> Response:
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


# ----------------------------------------------------------------------------
# Core verifier (single source of truth)
# ----------------------------------------------------------------------------
def verify_access_from_request(flask_request: Request) -> User:
    """
    Verify the JWT access token from Authorization header.

    Expected header:
      Authorization: Bearer <token>

    On success:
      • returns User
      • injects request.current_user, request.user_id (UUID), request.user_id_str
      • best-effort injects g.current_user

    On failure:
      • raises AuthError (401)
    """
    auth = flask_request.headers.get("Authorization") or ""
    if not auth.startswith("Bearer "):
        raise AuthError("Missing/invalid Authorization header", 401)

    token = auth.replace("Bearer ", "").strip()
    if not token:
        raise AuthError("Missing token", 401)

    try:
        payload = jwt_decode(token)
    except Exception:
        payload = None

    if not isinstance(payload, dict) or not payload:
        raise AuthError("Invalid or expired token", 401)

    raw_user_id = payload.get("sub") or payload.get("user_id") or payload.get("id")
    user_uuid = _to_uuid(raw_user_id)
    if user_uuid is None:
        raise AuthError("Token missing user identifier", 401)

    # DB lookup (UUID PK -> pass uuid.UUID)
    user = db.session.get(User, user_uuid)  # type: ignore[attr-defined]
    if user is None or not bool(getattr(user, "is_active", True)):
        raise AuthError("User not found or inactive", 401)

    # Inject for downstream code (compat)
    setattr(flask_request, "user_id", user_uuid)
    setattr(flask_request, "user_id_str", str(user_uuid))
    setattr(flask_request, "current_user", user)

    # Also attach on the global proxy (some code reads request.* directly)
    try:
        setattr(request, "user_id", user_uuid)           # type: ignore[attr-defined]
        setattr(request, "user_id_str", str(user_uuid))  # type: ignore[attr-defined]
        setattr(request, "current_user", user)           # type: ignore[attr-defined]
    except Exception:
        pass

    # Best-effort g.current_user
    try:
        setattr(g, "current_user", user)
    except Exception:
        pass

    return user


# ----------------------------------------------------------------------------
# Decorators
# ----------------------------------------------------------------------------
def require_access_token(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Require a valid JWT access token.

    Use when you only need authentication (no role check).
    """
    @wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs):  # type: ignore[no-untyped-def]
        flask_request = cast(Request, request)
        try:
            verify_access_from_request(flask_request)
        except AuthError as exc:
            return _json_error(str(exc), exc.status_code)
        except Exception:
            return _json_error("Unauthorized", 401)

        return fn(*args, **kwargs)

    return cast(Callable[P, R], wrapper)


def require_auth(*allowed_roles: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Backward-compatible decorator:

      @require_auth("admin")          -> token required + role must be admin
      @require_auth("admin","farmer") -> token required + role in set
      @require_auth()                 -> token required only

    IMPORTANT:
      allowed_roles are role NAMES:
        "admin" | "farmer" | "customer"
    """
    normalized = {r.strip().lower() for r in allowed_roles if isinstance(r, str) and r.strip()}

    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        @wraps(fn)
        @require_access_token
        def wrapped(*args: P.args, **kwargs: P.kwargs):  # type: ignore[no-untyped-def]
            if normalized:
                u = getattr(request, "current_user", None)
                if not isinstance(u, User):
                    return _json_error("Unauthorized", 401)

                if _role_name(u) not in normalized:
                    return _json_error("Forbidden", 403)

            return fn(*args, **kwargs)

        return cast(Callable[P, R], wrapped)

    return decorator


__all__ = [
    "AuthError",
    "verify_access_from_request",
    "require_access_token",
    "require_auth",
]
