# ============================================================================
# backend/routes/events.py — Customer Events API (Search + View + Like)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Lightweight event ingestion for analytics & AI features.
#
# EVENTS STORED:
#   • customer_search_events (query text)
#   • product_engagement_events (view/like/unlike)
#
# WHY THIS EXISTS:
#   AI Trends requires real signals:
#     - customer searches
#     - product views/likes
#     - orders (already exist)
# ============================================================================

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional, cast

import flask as _flask
from sqlalchemy import text

from backend.database.db import db
from backend.models.user import User
from backend.security import token_required

flask: Any = cast(Any, _flask)
ResponseT = Any

events_bp = flask.Blueprint("events", __name__)

def _json(payload: Any, status: int = 200) -> ResponseT:
    r = flask.jsonify(payload)
    r.status_code = status
    return r

def _current_user() -> Optional[User]:
    u = getattr(flask.request, "current_user", None)
    return u if isinstance(u, User) else None

def _to_uuid(v: Any) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(v))
    except Exception:
        return None

@events_bp.post("/search", strict_slashes=False)
@token_required
def track_search() -> ResponseT:
    """
    POST /api/events/search
    Body: { "query": "tomato" }
    """
    user = _current_user()
    payload = flask.request.get_json(silent=True) or {}
    q = str(payload.get("query") or "").strip()
    if not q:
        return _json({"success": False, "message": "query is required"}, 400)

    db.session.execute(
        text(
            "INSERT INTO customer_search_events (user_id, query, created_at) "
            "VALUES (:uid, :q, :ts)"
        ),
        {"uid": str(user.id) if user else None, "q": q, "ts": datetime.utcnow()},
    )
    db.session.commit()
    return _json({"success": True}, 201)

@events_bp.post("/product", strict_slashes=False)
@token_required
def track_product_event() -> ResponseT:
    """
    POST /api/events/product
    Body: { "product_id": "<uuid>", "event_type": "view|like|unlike" }
    """
    user = _current_user()
    payload = flask.request.get_json(silent=True) or {}
    pid = _to_uuid(payload.get("product_id"))
    et = str(payload.get("event_type") or "").strip().lower()

    if not pid:
        return _json({"success": False, "message": "product_id is required"}, 400)
    if et not in {"view", "like", "unlike"}:
        return _json({"success": False, "message": "invalid event_type"}, 400)

    db.session.execute(
        text(
            "INSERT INTO product_engagement_events (user_id, product_id, event_type, created_at) "
            "VALUES (:uid, :pid, :et, :ts)"
        ),
        {"uid": str(user.id) if user else None, "pid": str(pid), "et": et, "ts": datetime.utcnow()},
    )
    db.session.commit()
    return _json({"success": True}, 201)
