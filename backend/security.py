# ====================================================================
# backend/security.py — Auth & Service Token Decorators (CONSISTENT)
# ====================================================================
# FILE ROLE:
#   • Single public auth/RBAC surface for backend routes
#   • Human authentication: token_required / require_admin / require_farmer
#   • Internal auth: service_token_required (AI service calls)
#
# DESIGN GOALS:
#   • One source of truth for human auth and RBAC
#   • Consistent injection of request.current_user
#   • Lightweight compatibility with older imports
# ====================================================================

from __future__ import annotations

import os
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, cast, ParamSpec

from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Request

from backend.models.user import ROLE_ADMIN, ROLE_FARMER, User
from backend.utils.require_auth import require_access_token, require_auth

P = ParamSpec("P")
R = TypeVar("R")


# --------------------------------------------------------------------
# Shared helper
# --------------------------------------------------------------------
def get_current_user() -> Optional[User]:
    """
    Read the authenticated user injected by require_access_token.
    """
    u = getattr(request, "current_user", None)
    return u if isinstance(u, User) else None


# --------------------------------------------------------------------
# Human JWT auth (ACCESS ONLY)
# --------------------------------------------------------------------
def token_required(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Backward-compatible alias to the canonical access-token decorator.
    """
    return cast(Callable[P, R], require_access_token(fn))


def jwt_required(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Legacy alias kept for compatibility with older route code.
    """
    return token_required(fn)


def admin_required(fn: Callable[P, R]) -> Callable[P, R]:
    """
    ADMIN-only guard built on the canonical role-aware auth decorator.
    """
    return cast(Callable[P, R], require_auth("admin")(fn))


def require_admin(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Explicit RBAC alias used by some route modules.
    """
    return admin_required(fn)


def require_farmer(fn: Callable[P, R]) -> Callable[P, R]:
    """
    FARMER-only guard built on the canonical role-aware auth decorator.
    """
    return cast(Callable[P, R], require_auth("farmer")(fn))


# --------------------------------------------------------------------
# Internal service-to-service auth (AI service)
# --------------------------------------------------------------------
def service_token_required(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Require X-Service-Token for internal calls (e.g., AI service → backend).
    """

    @wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
        flask_request = cast(Request, request)
        provided = flask_request.headers.get("X-Service-Token", "").strip()
        expected = (os.getenv("BACKEND_SERVICE_TOKEN") or os.getenv("SERVICE_TOKEN") or "").strip()

        if not expected or provided != expected:
            resp = jsonify({"success": False, "message": "Unauthorized service"})
            resp.status_code = 401
            return resp

        return fn(*args, **kwargs)

    return cast(Callable[P, R], wrapper)


__all__ = [
    "get_current_user",
    "token_required",
    "jwt_required",
    "admin_required",
    "require_admin",
    "require_farmer",
    "service_token_required",
]
