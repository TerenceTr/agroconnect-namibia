# ====================================================================
# backend/middleware/roles.py — Role Guards (PYLANCE-CLEAN)
# --------------------------------------------------------------------
# FILE ROLE:
#   Reusable decorators for Role-Based Access Control (RBAC).
#
# WHY THIS FILE IS UPDATED:
#   Pylance can sometimes flag:
#     "ROLE_ADMIN is unknown import symbol"
#   when importing constants directly. Importing the MODULE is more robust.
# ====================================================================

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar, cast

from flask.globals import g
from flask.json import jsonify

F = TypeVar("F", bound=Callable[..., Any])

# --------------------------------------------------------------------
# Role constants (read from backend.models.user if present, else fallback)
# --------------------------------------------------------------------
try:
    import backend.models.user as user_model  # import module, not symbols

    ROLE_ADMIN: int | str = getattr(user_model, "ROLE_ADMIN", 1)
    ROLE_FARMER: int | str = getattr(user_model, "ROLE_FARMER", 2)
except Exception:  # pragma: no cover
    ROLE_ADMIN = 1
    ROLE_FARMER = 2


def _role_matches(actual: Any, required: int | str) -> bool:
    """Support int roles (1/2/3) and string roles ("admin"/"farmer") safely."""
    if actual is None:
        return False
    if isinstance(actual, str) or isinstance(required, str):
        return str(actual).strip().lower() == str(required).strip().lower()
    return actual == required


def _forbidden(message: str = "Forbidden"):
    """Standard 403 JSON response (Response object, decorator-safe)."""
    resp = jsonify({"success": False, "message": message})
    resp.status_code = 403
    return resp


def require_admin(fn: F) -> F:
    """Allow only ADMIN users (expects g.current_user set by auth middleware)."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        user = getattr(g, "current_user", None)
        role = getattr(user, "role", None)
        if not user or not _role_matches(role, ROLE_ADMIN):
            return _forbidden("Admin access required")
        return fn(*args, **kwargs)

    return cast(F, wrapper)


def require_farmer(fn: F) -> F:
    """Allow only FARMER users (expects g.current_user set by auth middleware)."""

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        user = getattr(g, "current_user", None)
        role = getattr(user, "role", None)
        if not user or not _role_matches(role, ROLE_FARMER):
            return _forbidden("Farmer access required")
        return fn(*args, **kwargs)

    return cast(F, wrapper)
