# ============================================================================
# backend/routes/ratings.py — Ratings API (Farmer rollups + Product views)
# ----------------------------------------------------------------------------
# ✅ FILE ROLE:
#   • Farmer dashboard: rating rollups (avg + count + recent)
#   • Product pages: list ratings for a product
#   • Auth: submit a rating (simple version)
#
# PREFIX RULE:
#   • DO NOT hardcode "/api" here.
#   • Registry mounts this blueprint at: /api/ratings
#
# ENDPOINTS:
#   • GET  /farmer/<farmer_id>?days=7&limit=20
#   • GET  /?product_id=<uuid>&limit=50
#   • POST /   (JWT required)
#
# PYRIGHT FIX:
#   Avoid int(x) / UUID(x) when x may be None/Unknown.
#   Convert through str(...) first and guard empties.
# ============================================================================

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import func, select

from backend.database.db import db
from backend.models.product import Product
from backend.models.user import User
from backend.utils.require_auth import require_access_token

# Rating is optional in some builds; if missing, fail gracefully.
try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]


ratings_bp = Blueprint("ratings", __name__)


# ----------------------------------------------------------------------------
# Helpers (Pyright-safe parsing)
# ----------------------------------------------------------------------------
def _utc_now_naive() -> datetime:
    return datetime.utcnow()


def _to_uuid(value: Any) -> Optional[UUID]:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return UUID(raw)
    except Exception:
        return None


def _to_int(value: Any, default: int) -> int:
    raw = str(value or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _json_error(message: str, status: int) -> Any:
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


# ----------------------------------------------------------------------------
# GET /api/ratings/farmer/<farmer_id>
# ----------------------------------------------------------------------------
@ratings_bp.get("/farmer/<string:farmer_id>", strict_slashes=False)
def farmer_ratings(farmer_id: str) -> Any:
    """
    Farmer rating rollup + recent items.

    Accept farmer id in:
      • /farmer/<farmer_id>
      • ?farmerId=<uuid> or ?farmer_id=<uuid>
    """
    if Rating is None:
        return _json_error("Ratings module not available", 501)

    fid = _to_uuid(farmer_id) or _to_uuid(request.args.get("farmerId")) or _to_uuid(request.args.get("farmer_id"))
    if not fid:
        return _json_error("Invalid farmerId", 400)

    days = max(1, min(_to_int(request.args.get("days"), 7), 365))
    limit = max(1, min(_to_int(request.args.get("limit"), 20), 100))
    since = _utc_now_naive() - timedelta(days=days)

    # Aggregate avg + count for ratings on products owned by farmer
    agg_stmt = (
        select(
            func.coalesce(func.avg(Rating.rating_score), 0),
            func.count(Rating.id),
        )
        .select_from(Rating)
        .join(Product, Rating.product_id == Product.id)
        .where(Product.farmer_id == fid)
        .where(Rating.created_at >= since)
    )

    row = db.session.execute(agg_stmt).first()
    avg_rating = float((row[0] if row else 0) or 0)
    count_rating = int((row[1] if row else 0) or 0)

    recent_stmt = (
        select(Rating)
        .join(Product, Rating.product_id == Product.id)
        .where(Product.farmer_id == fid)
        .where(Rating.created_at >= since)
        .order_by(Rating.created_at.desc())
        .limit(limit)
    )
    items = db.session.scalars(recent_stmt).all()

    return jsonify(
        {
            "success": True,
            "message": "OK",
            "farmerId": str(fid),
            "days": days,
            "averageRating": avg_rating,
            "totalRatings": count_rating,
            "ratings": [r.to_dict() for r in items],
        }
    )


# ----------------------------------------------------------------------------
# GET /api/ratings?product_id=<uuid>
# ----------------------------------------------------------------------------
@ratings_bp.get("/", strict_slashes=False)
def list_ratings() -> Any:
    """List ratings for a single product (useful for product detail pages)."""
    if Rating is None:
        return _json_error("Ratings module not available", 501)

    pid = _to_uuid(request.args.get("product_id"))
    if not pid:
        return _json_error("product_id is required", 400)

    limit = max(1, min(_to_int(request.args.get("limit"), 50), 200))

    stmt = (
        select(Rating)
        .where(Rating.product_id == pid)
        .order_by(Rating.created_at.desc())
        .limit(limit)
    )
    items = db.session.scalars(stmt).all()
    return jsonify({"success": True, "ratings": [r.to_dict() for r in items]})


# ----------------------------------------------------------------------------
# POST /api/ratings  (JWT required)
# ----------------------------------------------------------------------------
@ratings_bp.post("/", strict_slashes=False)
@require_access_token
def submit_rating() -> Any:
    """
    Submit a rating.

    Expected JSON:
      {
        "product_id": "<uuid>",
        "rating_score": 1..5,
        "comments": "optional",
        "order_id": "optional uuid"
      }
    """
    if Rating is None:
        return _json_error("Ratings module not available", 501)

    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _json_error("Unauthorized", 401)

    data = request.get_json(silent=True) or {}

    pid = _to_uuid(data.get("product_id"))
    if not pid:
        return _json_error("product_id is required", 400)

    product = db.session.get(Product, pid)
    if not product:
        return _json_error("Product not found", 404)

    score = _to_int(data.get("rating_score"), -1)
    if score < 1 or score > 5:
        return _json_error("rating_score must be between 1 and 5", 400)

    order_id = _to_uuid(data.get("order_id"))
    comments_raw = str(data.get("comments") or "").strip()
    comments = comments_raw or None

    r = Rating()
    r.product_id = product.id
    r.user_id = current_user.id
    r.rating_score = score
    r.comments = comments
    if order_id is not None:
        r.order_id = order_id

    db.session.add(r)
    db.session.commit()

    resp = jsonify({"success": True, "message": "Rating submitted", "rating": r.to_dict()})
    resp.status_code = 201
    return resp
