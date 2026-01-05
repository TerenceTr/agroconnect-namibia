# ====================================================================
# backend/utils/auth_helpers.py — JWT Request Validation
# ====================================================================
# FILE ROLE:
#   • Extracts and validates ACCESS JWT from an incoming Flask request
#   • Returns authenticated user_id (UUID)
#   • Raises explicit errors (handled by higher-level decorators/middleware)
#
# WHY THIS FIX:
#   Pyright may report: `"Request" is unknown import symbol`
#   because Request is not always exported in Flask type stubs as `flask.Request`.
#   The correct typing import is from `flask.wrappers` (Flask's Request wrapper).
# ====================================================================

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

# --------------------------------------------------------------------
# TYPE-SAFE REQUEST IMPORT
# --------------------------------------------------------------------
# Use flask.wrappers.Request for typing (stable across Flask versions/stubs).
# We put it behind TYPE_CHECKING so it doesn't affect runtime imports.
if TYPE_CHECKING:
    from flask.wrappers import Request

from backend.utils.jwt_utils import jwt_decode


class AuthError(Exception):
    """Raised when authentication fails (missing/invalid token)."""


def verify_access_from_request(request: "Request") -> UUID:
    """
    Validate `Authorization: Bearer <token>` header.

    Args:
        request: Flask request object (passed in explicitly for testability)

    Returns:
        UUID of the authenticated user (from JWT 'sub' claim)

    Raises:
        AuthError: if header/token is missing, malformed, or invalid
    """
    # --- Read header safely (default to empty string) ----------------
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise AuthError("Missing Authorization header")

    # --- Extract token part -----------------------------------------
    token = auth[len("Bearer ") :].strip()
    if not token:
        raise AuthError("Missing bearer token")

    # --- Decode JWT --------------------------------------------------
    decoded = jwt_decode(token)

    # --- Enforce token purpose (access vs refresh) -------------------
    if decoded.get("purpose") != "access":
        raise AuthError("Invalid token purpose")

    # --- Extract subject/user id ------------------------------------
    sub = decoded.get("sub")
    if not sub:
        raise AuthError("Token subject missing")

    try:
        return UUID(str(sub))
    except Exception as exc:
        raise AuthError("Invalid user ID in token") from exc
