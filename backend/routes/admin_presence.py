# ====================================================================
# backend/routes/admin_presence.py — Admin Presence (Online/Offline)
# ====================================================================
# FILE ROLE:
#   • Admin-only endpoint to retrieve online user IDs + last_seen map
# ====================================================================

from __future__ import annotations

from typing import Any

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify

from backend.models.user import ROLE_ADMIN, User
from backend.services.presence_store import snapshot
from backend.utils.require_auth import require_access_token

admin_presence_bp = Blueprint("admin_presence", __name__)


@admin_presence_bp.get("/users")
@require_access_token
def users_presence() -> Any:
    user = getattr(request, "current_user", None)
    if not isinstance(user, User) or user.role != ROLE_ADMIN:
        resp = jsonify({"success": False, "message": "Forbidden"})
        resp.status_code = 403
        return resp

    last_seen_iso, online_ids = snapshot()
    return jsonify({"success": True, "online_ids": online_ids, "last_seen": last_seen_iso})
