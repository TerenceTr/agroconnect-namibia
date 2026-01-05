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
# PYRIGHT / PYDANCE NOTES:
#   • PyJWT's stubs can be loose/strict depending on version.
#   • jwt.encode may return str (PyJWT v2+) or bytes (older) → normalize.
#   • jwt.decode returns dict[str, Any] → cast to a TypedDict with total=False.
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
    Normalize token output to str across PyJWT versions.

    PyJWT v2+: returns str
    Older / some stubs: may be bytes
    """
    if isinstance(token, str):
        return token
    if isinstance(token, (bytes, bytearray)):
        return token.decode("utf-8")
    return str(token)


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
          Should include at least {"sub": "<uuid-string>"}.
          (We do not enforce it here to keep this utility generic.)
        purpose:
          "access" or "refresh"
        hours:
          token validity window

    Returns:
        JWT token string.
    """
    now = dt.datetime.now(timezone.utc)
    exp = now + dt.timedelta(hours=int(hours))

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
    """
    decoded = jwt.decode(token, _get_secret(), algorithms=["HS256"])

    # jwt.decode returns a dict-like; we cast to our TypedDict.
    # Callers should use decoded.get("sub") and decoded.get("purpose").
    return cast(DecodedJWT, decoded)
