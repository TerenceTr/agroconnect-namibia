# ====================================================================
# backend/routes/presence.py — Presence Ping API (JWT-PROTECTED)
# ====================================================================
# FILE ROLE:
#   • Lightweight endpoint to update "last seen" for the authenticated user.
#   • Powers admin online/offline view (in-memory store by default).
#
# ROUTES (registered at url_prefix="/api/presence"):
#   POST /api/presence/ping
#
# USED BY:
#   DashboardLayout.jsx (periodic ping)
#
# NOTE:
#   Presence is an OPTIONAL feature. If anything fails (Redis down, etc),
#   we still return success so the app never breaks.
# ====================================================================

from __future__ import annotations

from typing import Any

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify

from backend.models.user import User
from backend.services.presence_store import touch
from backend.utils.require_auth import require_access_token

presence_bp = Blueprint("presence", __name__)


def _json_error(msg: str, status: int) -> Any:
    resp = jsonify({"success": False, "message": msg})
    resp.status_code = status
    return resp


@presence_bp.post("/ping")
@require_access_token
def ping() -> Any:
    """Ping presence.

    Intentionally tolerant:
      • If presence storage fails, we still return success (optional feature).
    """
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    try:
        touch(str(user.id))
    except Exception:
        # Presence is optional — never break the UI/auth flow
        pass

    return jsonify({"success": True, "user_id": str(user.id)})
