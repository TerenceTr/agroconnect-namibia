# ============================================================================
# backend/middleware/jwt_required.py — JWT Access Middleware (COMPAT)
# ============================================================================
# FILE ROLE:
#   Compatibility decorator for code that still imports/uses @jwt_required.
#   Delegates verification to backend.utils.require_auth.verify_access_from_request
#   so you maintain ONE auth logic source of truth.
#
# INJECTS (legacy expectations):
#   • request.user_id      -> UUID
#   • request.current_user -> User
#   • g.current_user       -> User
#
# PYLANCE FIX:
#   Import request/g/jsonify from Flask submodules to avoid "unknown import symbol".
# ============================================================================

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar, cast, TYPE_CHECKING
from uuid import UUID

from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Request, Response

from backend.models.user import User
from backend.utils.require_auth import AuthError, verify_access_from_request

if TYPE_CHECKING:
    from flask.ctx import _AppCtxGlobals

F = TypeVar("F", bound=Callable[..., Any])


def _unauthorized(message: str, status: int = 401) -> Response:
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


def jwt_required(fn: F) -> F:
    """
    Protect a route using ACCESS JWT (compat wrapper).
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        flask_request = cast(Request, request)

        try:
            user: User = verify_access_from_request(flask_request)
        except AuthError as exc:
            return _unauthorized(str(exc), exc.status_code)
        except Exception:
            return _unauthorized("Unauthorized", 401)

        # Attach for legacy code
        user_id = cast(UUID, user.id)
        setattr(request, "user_id", user_id)
        setattr(request, "current_user", user)

        try:
            flask_g = cast("_AppCtxGlobals", g)
            flask_g.current_user = user
        except Exception:
            setattr(g, "current_user", user)

        return fn(*args, **kwargs)

    return cast(F, wrapper)
