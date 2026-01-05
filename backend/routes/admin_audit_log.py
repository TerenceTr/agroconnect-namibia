# ====================================================================
# backend/routes/admin_audit_log.py — Admin Audit Log (JWT)
# --------------------------------------------------------------------
# FILE ROLE:
#   Powers AuditLogPage.
#
# ROUTE:
#   GET /api/admin/audit-log
#
# FIX INCLUDED:
#   Pylance/Pyright error:
#     "Cannot access attribute 'deleted_at' for class 'type[User]'"
#   is fixed by ensuring User.deleted_at is a mapped column (see updated User model)
#   and by keeping query expressions column-safe.
# ====================================================================

from __future__ import annotations

from typing import Any, Optional, cast

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response

from sqlalchemy import select

from backend.database.db import db
from backend.models.user import ROLE_ADMIN, User
from backend.utils.require_auth import require_access_token

admin_audit_bp = Blueprint("admin_audit", __name__)


def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return cast(Response, resp)


def _current_user() -> Optional[User]:
    u = getattr(g, "current_user", None)
    if isinstance(u, User):
        return u
    u2 = getattr(request, "current_user", None)
    if isinstance(u2, User):
        return u2
    return None


def _admin_guard() -> Optional[Response]:
    u = _current_user()
    if u is None:
        return _json({"success": False, "message": "Authentication required"}, 401)
    if int(getattr(u, "role", 0) or 0) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)
    return None


@admin_audit_bp.route("/audit-log", methods=["GET"])
@require_access_token
def audit_log() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    # Derived logs from soft-deleted users
    deleted_at_col = cast(Any, getattr(User, "deleted_at", None))
    if deleted_at_col is None:
        # If the column ever disappears in a future schema, fail gracefully.
        return _json({"logs": []}, 200)

    stmt = (
        select(User.id, User.email, deleted_at_col)
        .where(deleted_at_col.is_not(None))
        .order_by(deleted_at_col.desc())
        .limit(200)
    )

    rows = db.session.execute(stmt).all()

    logs: list[dict[str, Any]] = []
    for user_id, email, deleted_at in rows:
        logs.append(
            {
                "id": str(user_id),
                "deleted_email": email,
                "actor_role": "system",
                "reason": "Account deletion (soft-delete)",
                "deleted_at": deleted_at.isoformat() if deleted_at else None,
            }
        )

    return _json({"logs": logs}, 200)
