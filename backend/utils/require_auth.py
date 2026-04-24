# ============================================================================
# backend/utils/require_auth.py — JWT Access Guard (Single Source of Truth)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Single source of truth for verifying JWT access tokens and injecting the
#   authenticated user into the Flask request context.
#
# UPDATED DESIGN:
#   ✅ verifies Bearer access tokens
#   ✅ injects request.current_user / request.user_id / request.user_id_str
#   ✅ keeps presence/live activity updated in memory when available
#   ✅ updates users.last_seen_at if the DB column exists
#   ✅ DOES NOT write "seen" rows into login_events anymore
#   ✅ preserves clean 204 handling for CORS preflight OPTIONS requests
#
# IMPORTANT ARCHITECTURE RULE:
#   login_events is reserved for AUTH / SESSION events only:
#     • login
#     • logout
#     • logout_all
#     • refresh
#     • failed_login
#     • session_expired
#     • token_revoked
#
#   Presence / heartbeat / per-request auth validation MUST NOT be stored in
#   login_events, otherwise login statistics become inaccurate.
#
# WHY THIS CHANGE:
#   The previous version inserted throttled "seen" rows into login_events.
#   That polluted audit/reporting and caused "login statistics" to count
#   general activity instead of true logins.
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Callable, Optional, ParamSpec, TypeVar, cast

from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Request, Response
from sqlalchemy import inspect, text

from backend.database.db import db
from backend.models.user import User
from backend.utils.jwt_utils import jwt_decode

P = ParamSpec("P")
R = TypeVar("R")


class AuthError(Exception):
    """
    Explicit auth-layer exception so route decorators can return the correct
    HTTP status code and JSON payload.
    """

    def __init__(self, message: str = "Unauthorized", status_code: int = 401) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code

    def __str__(self) -> str:
        return self.message


# ----------------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------------
def _to_uuid(value: Any) -> Optional[uuid.UUID]:
    if value is None:
        return None
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    try:
        text_value = str(value).strip()
    except Exception:
        return None
    return text_value or None


def _role_name(user: User) -> str:
    """
    Normalize user role to a canonical lowercase role name.
    """
    rn = getattr(user, "role_name", None)
    if isinstance(rn, str) and rn.strip():
        return rn.strip().lower()

    role_raw = getattr(user, "role", None)
    try:
        role_int = int(role_raw) if role_raw is not None else 3
    except Exception:
        role_int = 3

    return {1: "admin", 2: "farmer", 3: "customer"}.get(role_int, "customer")


def _json_error(message: str, status: int) -> Response:
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return cast(Response, resp)


def _options_ok() -> Response:
    """
    Clean OPTIONS response for browser preflight.
    """
    return Response("", status=204)


def _request_id(req: Request) -> Optional[str]:
    """
    Optional correlation/request ID from incoming headers.

    This is not required for auth to function, but it is useful for tracing and
    later audit/report improvements.
    """
    return (
        _safe_str(req.headers.get("X-Request-ID"))
        or _safe_str(req.headers.get("X-Correlation-ID"))
        or _safe_str(req.headers.get("X-Trace-ID"))
    )


# ----------------------------------------------------------------------------
# Best-effort DB support detection
# ----------------------------------------------------------------------------
_LAST_SEEN_WRITE_AT: dict[uuid.UUID, datetime] = {}
_LAST_SEEN_THROTTLE = timedelta(seconds=60)

_TABLE_CACHE: dict[str, Optional[bool]] = {
    "users_last_seen_at": None,
}


def _has_users_last_seen_at_column() -> bool:
    """
    Check whether users.last_seen_at exists in the database.

    We keep this defensive because the ORM model and the physical DB may not
    always evolve at the same time during development.
    """
    cached = _TABLE_CACHE.get("users_last_seen_at")
    if isinstance(cached, bool):
        return cached

    try:
        insp = inspect(db.engine)
        cols = insp.get_columns("users")
        ok = any((c.get("name") == "last_seen_at") for c in (cols or []))
        _TABLE_CACHE["users_last_seen_at"] = ok
        return ok
    except Exception:
        _TABLE_CACHE["users_last_seen_at"] = False
        return False


def _touch_last_seen(*, user_id: uuid.UUID) -> None:
    """
    Best-effort, throttled update of users.last_seen_at.

    IMPORTANT:
      This updates the user's current presence freshness only.
      It does NOT insert into login_events.
    """
    now = datetime.utcnow()

    last_write = _LAST_SEEN_WRITE_AT.get(user_id)
    if last_write and (now - last_write) < _LAST_SEEN_THROTTLE:
        return

    _LAST_SEEN_WRITE_AT[user_id] = now

    if not _has_users_last_seen_at_column():
        return

    try:
        with db.engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET last_seen_at = :ts WHERE id = :uid"),
                {"ts": now, "uid": str(user_id)},
            )
    except Exception:
        # Never break the request because last_seen_at failed.
        return


def _mark_presence_active(user_id: uuid.UUID) -> None:
    """
    Best-effort in-memory presence touch.
    """
    try:
        from backend.utils.presence import mark_active

        mark_active(str(user_id))
    except Exception:
        pass

    try:
        from backend.services.presence_store import touch

        touch(str(user_id))
    except Exception:
        pass


# ----------------------------------------------------------------------------
# Core auth verification
# ----------------------------------------------------------------------------
def verify_access_from_request(flask_request: Request) -> User:
    """
    Verify a Bearer access token from the current request and inject the user
    into request/g context.

    Side effects:
      • request.user_id
      • request.user_id_str
      • request.current_user
      • g.current_user
      • g.request_id (best effort)
      • presence / last_seen_at refresh (best effort)

    NOTE:
      This function does NOT write audit/session rows. Auth/session audit is
      handled explicitly in auth routes such as /login, /logout, /refresh.
    """
    auth = flask_request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise AuthError("Missing/invalid Authorization header", 401)

    token = auth.split(" ", 1)[1].strip()
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

    # Flask-SQLAlchemy typed access may trigger static checker noise, but this is
    # the simplest and most reliable runtime lookup.
    user = db.session.get(User, user_uuid)  # type: ignore[attr-defined]
    if user is None or not bool(getattr(user, "is_active", True)):
        raise AuthError("User not found or inactive", 401)

    # ------------------------------------------------------------------------
    # Inject into the request context for downstream routes
    # ------------------------------------------------------------------------
    setattr(flask_request, "user_id", user_uuid)
    setattr(flask_request, "user_id_str", str(user_uuid))
    setattr(flask_request, "current_user", user)

    try:
        setattr(request, "user_id", user_uuid)  # type: ignore[attr-defined]
        setattr(request, "user_id_str", str(user_uuid))  # type: ignore[attr-defined]
        setattr(request, "current_user", user)  # type: ignore[attr-defined]
    except Exception:
        pass

    try:
        setattr(g, "current_user", user)
        setattr(g, "request_id", _request_id(flask_request))
    except Exception:
        pass

    # ------------------------------------------------------------------------
    # Best-effort live presence refresh
    # ------------------------------------------------------------------------
    try:
        _mark_presence_active(user_uuid)
    except Exception:
        pass

    # ------------------------------------------------------------------------
    # Best-effort DB freshness refresh
    # IMPORTANT:
    #   This is presence freshness only, not audit logging.
    # ------------------------------------------------------------------------
    try:
        _touch_last_seen(user_id=user_uuid)
    except Exception:
        pass

    return user


# ----------------------------------------------------------------------------
# Decorators
# ----------------------------------------------------------------------------
def require_access_token(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Require a valid access token for the wrapped route.

    OPTIONS requests are allowed through with a 204 so browser preflight checks
    do not get blocked by authentication logic.
    """

    @wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs):
        flask_request = cast(Request, request)

        if flask_request.method == "OPTIONS":
            return cast(Any, _options_ok())

        try:
            verify_access_from_request(flask_request)
        except AuthError as exc:
            return cast(Any, _json_error(str(exc), exc.status_code))
        except Exception:
            return cast(Any, _json_error("Unauthorized", 401))

        return fn(*args, **kwargs)

    return cast(Callable[P, R], wrapper)


def require_auth(*allowed_roles: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """
    Role-aware auth decorator.

    Example:
      @require_auth("admin")
      @require_auth("admin", "farmer")
    """
    normalized = {
        r.strip().lower()
        for r in allowed_roles
        if isinstance(r, str) and r.strip()
    }

    def decorator(fn: Callable[P, R]) -> Callable[P, R]:
        @wraps(fn)
        @require_access_token
        def wrapped(*args: P.args, **kwargs: P.kwargs):
            if normalized:
                u = getattr(request, "current_user", None)
                if not isinstance(u, User):
                    return cast(Any, _json_error("Unauthorized", 401))
                if _role_name(u) not in normalized:
                    return cast(Any, _json_error("Forbidden", 403))
            return fn(*args, **kwargs)

        return cast(Callable[P, R], wrapped)

    return decorator


__all__ = [
    "AuthError",
    "verify_access_from_request",
    "require_access_token",
    "require_auth",
]