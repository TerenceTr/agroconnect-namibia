# ====================================================================
# backend/utils/jwt_utils.py — JWT Encode/Decode Helpers (HS256)
# --------------------------------------------------------------------
# FILE ROLE:
#   Central JWT utility used by:
#     • backend/routes/auth.py (issue tokens)
#     • backend/utils/require_auth.py (verify access tokens)
#     • backend/utils/auth_helpers.py (request header validation)
#
# DESIGN:
#   • HS256 symmetric signing
#   • UTC-aware exp/iat (timezone-aware datetimes)
#   • TypedDict-safe decode (callers use .get() instead of ["sub"])
#
# PYRIGHT / PYLANCE NOTES (WHY THIS FILE EXISTS):
#   PyJWT type stubs vary by version.
#   Common stub issue fixed here:
#     - jwt.decode(..., algorithms=...) expects list[str] | None
#       but some code passes Sequence[str] which triggers:
#         "Argument of type 'Sequence[str]' cannot be assigned to 'list[str] | None'"
#
#   FIX:
#     Always pass a concrete list[str] to algorithms.
# ====================================================================

from __future__ import annotations

import datetime as dt
from datetime import timezone
from typing import Any, Dict, Mapping, TypedDict, cast

import jwt
from flask.globals import current_app

# --------------------------------------------------------------------
# Public shape of a decoded JWT in our system.
# total=False means ALL keys are optional, so `.get()` is always safe.
# --------------------------------------------------------------------
class DecodedJWT(TypedDict, total=False):
    # Standard claims
    iat: Any
    exp: Any

    # Our custom claims
    purpose: str
    sub: str

    # Optional compatibility claims (some code may use these)
    user_id: str
    id: str


# --------------------------------------------------------------------
# Internal helpers
# --------------------------------------------------------------------
def _get_secret() -> str:
    """
    Read JWT secret from Flask config.

    Expected:
      app.config["JWT_SECRET"] = "..."
    """
    secret = current_app.config.get("JWT_SECRET")
    if not isinstance(secret, str) or not secret.strip():
        raise RuntimeError("JWT_SECRET must be a non-empty string")
    return secret.strip()


def _ensure_str(token: Any) -> str:
    """
    Normalize jwt.encode output to str across PyJWT versions.

    PyJWT v2+: returns str
    Older versions/stubs: may be bytes
    """
    if isinstance(token, str):
        return token
    if isinstance(token, (bytes, bytearray)):
        return bytes(token).decode("utf-8", errors="ignore")
    return str(token)


# --------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------
def jwt_encode(
    payload: Mapping[str, Any],
    *,
    purpose: str = "access",
    hours: int = 24,
) -> str:
    """
    Encode a JWT with standard claims.

    Args:
        payload:
          Typically includes {"sub": "<uuid-string>"}.
          (We keep this utility generic; enforcement happens in auth routes.)
        purpose:
          "access" or "refresh"
        hours:
          token validity window (clamped to >= 1)

    Returns:
        JWT token string.
    """
    hours_i = int(hours) if int(hours) >= 1 else 1

    now = dt.datetime.now(timezone.utc)
    exp = now + dt.timedelta(hours=hours_i)

    # Copy user payload into claims and add standard/custom fields.
    claims: Dict[str, Any] = dict(payload)
    claims["iat"] = now
    claims["exp"] = exp
    claims["purpose"] = purpose

    token = jwt.encode(claims, _get_secret(), algorithm="HS256")
    return _ensure_str(token)


def jwt_decode(token: str) -> DecodedJWT:
    """
    Decode and validate a JWT.

    Raises:
        jwt.ExpiredSignatureError, jwt.InvalidTokenError, etc.

    TYPE CHECKER FIX:
        Pass a concrete list[str] to `algorithms` to satisfy stricter stubs.
    """
    decoded = jwt.decode(
        token,
        _get_secret(),
        algorithms=["HS256"],  # ✅ list[str] (NOT Sequence[str]) for Pyright/Pylance
        options={
            # Keep defaults safe; caller decides how to handle errors.
            "verify_signature": True,
            "verify_exp": True,
        },
    )

    # jwt.decode returns Mapping[str, Any]; we cast to our TypedDict(total=False).
    # Callers should use decoded.get("sub") / decoded.get("purpose").
    return cast(DecodedJWT, decoded)
