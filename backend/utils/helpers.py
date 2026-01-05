# ====================================================================
# backend/utils/helpers.py — Shared API Helpers
# --------------------------------------------------------------------
# PURPOSE:
#   • Small reusable helpers for API responses
#   • Keeps routes concise and consistent
# ====================================================================

from typing import Any
from flask import jsonify


def upload_error(message: str, status: int = 400) -> Any:
    """
    Standardized upload error response.

    Used by all routes that handle file uploads.
    """
    return jsonify({"success": False, "error": message}), status
