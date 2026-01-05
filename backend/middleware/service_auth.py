# ====================================================================
# backend/middleware/service_auth.py — Backend ↔ AI Service Auth
# --------------------------------------------------------------------
# FILE ROLE:
#   Protect INTERNAL endpoints that are called by the AI microservice.
#
# SECURITY MODEL:
#   • AI service sends: X-Service-Token: <secret>
#   • Backend compares it to BACKEND_SERVICE_TOKEN in Flask config
#
# PYLANCE NOTE:
#   Import `request` and `current_app` from flask.globals to reduce
#   "unknown import symbol" warnings in some Flask typing setups.
# ====================================================================

from __future__ import annotations

from functools import wraps
from typing import Any, Callable, TypeVar, cast

from flask.globals import current_app, request
from flask.json import jsonify

F = TypeVar("F", bound=Callable[..., Any])


def _unauthorized(message: str = "Unauthorized service", status: int = 401):
    """Standard JSON unauthorized response (Response object, no tuple)."""
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


def service_token_required(fn: F) -> F:
    """
    Require a valid X-Service-Token header for internal service calls.
    """

    @wraps(fn)
    def wrapper(*args: Any, **kwargs: Any):
        token = request.headers.get("X-Service-Token", "")
        expected = current_app.config.get("BACKEND_SERVICE_TOKEN")

        # expected should be a string in config; handle missing config safely
        if not isinstance(expected, str) or not expected.strip():
            return _unauthorized("Service auth not configured", 500)

        if token != expected:
            return _unauthorized("Unauthorized service", 401)

        return fn(*args, **kwargs)

    return cast(F, wrapper)
