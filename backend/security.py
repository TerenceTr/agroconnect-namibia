# ====================================================================
# backend/security.py — Auth & Service Token Decorators (CONSISTENT)
# ====================================================================
# FILE ROLE:
#   • Human authentication: token_required / admin_required
#   • Internal auth: service_token_required (AI service calls)
#
# DESIGN GOALS:
#   • One source of truth for human auth (ACCESS tokens only)
#   • Consistent injection of request.current_user
#   • Pyright-friendly imports (request/jsonify from typed Flask submodules)
#
# IMPORTANT:
#   token_required is an alias for require_access_token (ACCESS ONLY).
#   This prevents refresh tokens from being accepted on protected endpoints.
# ====================================================================

from __future__ import annotations

import os
from functools import wraps
from typing import Any, Callable, Optional, TypeVar, cast, ParamSpec

from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Request

from backend.models.user import ROLE_ADMIN, User
from backend.utils.require_auth import require_access_token

P = ParamSpec("P")
R = TypeVar("R")


# --------------------------------------------------------------------
# Shared helper
# --------------------------------------------------------------------
def get_current_user() -> Optional[User]:
    """
    Read the authenticated user injected by require_access_token.

    WHY THIS HELPER EXISTS:
      • Flask's request is a LocalProxy, and dynamic attributes (current_user)
        confuse type checkers.
      • Centralizing access keeps routes clean and avoids repeating casts/ignores.
    """
    u = getattr(request, "current_user", None)
    return u if isinstance(u, User) else None


# --------------------------------------------------------------------
# Human JWT auth (ACCESS ONLY)
# --------------------------------------------------------------------
def token_required(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Alias to the single source of truth.
    require_access_token:
      • validates ACCESS token
      • injects request.current_user
    """
    return cast(Callable[P, R], require_access_token(fn))


def admin_required(fn: Callable[P, R]) -> Callable[P, R]:
    """
    ADMIN guard for endpoints.

    WHAT IT ENFORCES:
      • Valid ACCESS token (via require_access_token)
      • request.current_user.role == ROLE_ADMIN

    WHY UPDATED:
      • Many projects accidentally rely on decorator order:
          @token_required
          @admin_required
        If someone forgets @token_required, the route becomes inconsistent.
      • This decorator is now self-contained: it always applies access-token auth.
    """

    @wraps(fn)
    def _admin_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
        user = get_current_user()
        if not user:
            resp = jsonify({"success": False, "message": "Authentication required"})
            resp.status_code = 401
            return resp

        if getattr(user, "role", None) != ROLE_ADMIN:
            resp = jsonify({"success": False, "message": "Admin access required"})
            resp.status_code = 403
            return resp

        return fn(*args, **kwargs)

    # Apply ACCESS-token auth first (injects request.current_user), then admin check.
    return cast(Callable[P, R], require_access_token(_admin_wrapper))


# --------------------------------------------------------------------
# Internal service-to-service auth (AI service)
# --------------------------------------------------------------------
def service_token_required(fn: Callable[P, R]) -> Callable[P, R]:
    """
    Require X-Service-Token for internal calls (e.g., AI service → backend).

    Header:
      X-Service-Token: <token>

    Expected token is read from env:
      BACKEND_SERVICE_TOKEN (preferred)
      SERVICE_TOKEN         (fallback)
    """

    @wraps(fn)
    def wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
        # Cast LocalProxy to Request so Pyright recognizes .headers
        flask_request = cast(Request, request)
        provided = flask_request.headers.get("X-Service-Token", "").strip()

        expected = (os.getenv("BACKEND_SERVICE_TOKEN") or os.getenv("SERVICE_TOKEN") or "").strip()

        if not expected or provided != expected:
            resp = jsonify({"success": False, "message": "Unauthorized service"})
            resp.status_code = 401
            return resp

        return fn(*args, **kwargs)

    return cast(Callable[P, R], wrapper)
