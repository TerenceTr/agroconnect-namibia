# ============================================================================
# backend/routes/likes.py — Customer Product Likes (Cross-device favorites)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   REST API for liking/unliking products (+ bulk sync for local->DB migration).
#   Mounted under /api via register_blueprints().
#
# KEY FIXES IN THIS VERSION:
#   ✅ Pyright-friendly Flask imports.
#   ✅ SQLAlchemy 2.0 select()/delete() style.
#   ✅ NO direct like.to_dict() calls in routes.
#   ✅ Avoids class-level ProductLike.product loader dependency in query options
#      (fixes: "Cannot access attribute 'product' for class 'type[ProductLike]'").
#   ✅ Adds compatibility route aliases:
#        /likes...
#        /product-likes...
#   ✅ Bulk sync endpoint for one-time localStorage migration.
#   ✅ Defensive user-id and product-pk compatibility handling.
# ============================================================================

from __future__ import annotations

import uuid
from typing import Any, Dict, Iterable, List, Optional, Tuple

from flask.blueprints import Blueprint
from flask.globals import current_app, request
from flask.json import jsonify
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from backend.database.db import db
from backend.models.product import Product
from backend.models.product_like import ProductLike
from backend.utils.require_auth import require_auth

likes_bp = Blueprint("likes", __name__)


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def parse_uuid(value: Any) -> Optional[uuid.UUID]:
    """Safely parse UUID from input."""
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value).strip())
    except Exception:
        return None


def parse_int(value: Any, default: int, min_value: int, max_value: int) -> int:
    """Safe integer parsing + clamping."""
    try:
        n = int(value)
    except Exception:
        n = default

    if n < min_value:
        return min_value
    if n > max_value:
        return max_value
    return n


def current_user_id_from_request() -> Optional[uuid.UUID]:
    """
    Auth middleware stores current_user on request.
    Supports both modern (id) and legacy (user_id) fields.
    """
    user_obj: Any = getattr(request, "current_user", None)
    return parse_uuid(getattr(user_obj, "id", None) or getattr(user_obj, "user_id", None))


def dedupe_uuid_list(values: Iterable[Any]) -> List[uuid.UUID]:
    """Keep only valid unique UUIDs, preserving order."""
    out: List[uuid.UUID] = []
    seen: set[uuid.UUID] = set()
    for raw in values:
        uid = parse_uuid(raw)
        if uid is None or uid in seen:
            continue
        seen.add(uid)
        out.append(uid)
    return out


def _product_pk_col():
    """
    Product PK compatibility helper:
      - preferred: Product.product_id
      - fallback : Product.id
    """
    return getattr(Product, "product_id", None) or getattr(Product, "id", None)


def _serialize_like(like: ProductLike, product: Optional[Product] = None) -> Dict[str, Any]:
    """
    Pyright-safe serializer.

    IMPORTANT:
      We intentionally avoid `like.to_dict()` calls inside routes so strict
      type-checking does not fail when dynamic ORM methods are not inferred.
    """
    p = product
    if p is None:
        # Runtime-safe fallback if relationship is available.
        p = getattr(like, "product", None)

    product_name = None
    image_url = None
    category = None
    if p is not None:
        product_name = getattr(p, "product_name", None) or getattr(p, "name", None)
        image_url = getattr(p, "image_url", None)
        category = getattr(p, "category", None)

    created_at = getattr(like, "created_at", None)

    return {
        "like_id": str(getattr(like, "like_id", None) or ""),
        "id": str(getattr(like, "like_id", None) or ""),
        "user_id": str(getattr(like, "user_id", None) or ""),
        "product_id": str(getattr(like, "product_id", None) or ""),
        "created_at": created_at.isoformat() if created_at is not None else None,
        "product_name": product_name,
        "image_url": image_url,
        "category": category,
    }


def fetch_existing_like(user_id: uuid.UUID, product_id: uuid.UUID) -> Optional[ProductLike]:
    stmt = (
        select(ProductLike)
        .where(ProductLike.user_id == user_id, ProductLike.product_id == product_id)
        .limit(1)
    )
    return db.session.execute(stmt).scalars().first()


def load_user_likes(
    user_id: uuid.UUID, limit: int, offset: int
) -> Tuple[int, List[Tuple[ProductLike, Optional[Product]]]]:
    """
    Load likes + product metadata WITHOUT relying on `ProductLike.product` class
    attribute in query options (which can trigger Pyright errors in some setups).
    """
    total_stmt = select(func.count()).select_from(ProductLike).where(ProductLike.user_id == user_id)
    total = int(db.session.execute(total_stmt).scalar_one() or 0)

    pk_col = _product_pk_col()
    rows: List[Tuple[ProductLike, Optional[Product]]] = []

    if pk_col is None:
        # Fallback: likes only if Product PK cannot be resolved.
        likes_stmt = (
            select(ProductLike)
            .where(ProductLike.user_id == user_id)
            .order_by(ProductLike.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        likes = list(db.session.execute(likes_stmt).scalars().all())
        rows = [(lk, None) for lk in likes]
        return total, rows

    rows_stmt = (
        select(ProductLike, Product)
        .outerjoin(Product, ProductLike.product_id == pk_col)
        .where(ProductLike.user_id == user_id)
        .order_by(ProductLike.created_at.desc())
        .offset(offset)
        .limit(limit)
    )
    result = db.session.execute(rows_stmt).all()

    for row in result:
        like_obj = row[0]
        product_obj = row[1] if len(row) > 1 else None
        rows.append((like_obj, product_obj))

    return total, rows


# ----------------------------------------------------------------------------
# List likes
# ----------------------------------------------------------------------------
@likes_bp.get("/likes")
@likes_bp.get("/product-likes")
@require_auth("customer")
def list_likes():
    user_id = current_user_id_from_request()
    if user_id is None:
        return jsonify({"message": "Invalid user."}), 401

    limit = parse_int(request.args.get("limit"), default=500, min_value=1, max_value=2000)
    offset = parse_int(request.args.get("offset"), default=0, min_value=0, max_value=10_000_000)

    total, rows = load_user_likes(user_id, limit=limit, offset=offset)

    return jsonify(
        {
            "count": total,
            "likes": [_serialize_like(like, product) for like, product in rows],
        }
    ), 200


# ----------------------------------------------------------------------------
# Like product (POST/PUT for compatibility)
# ----------------------------------------------------------------------------
@likes_bp.route("/likes/<product_id>", methods=["POST", "PUT"])
@likes_bp.route("/product-likes/<product_id>", methods=["POST", "PUT"])
@require_auth("customer")
def like_product(product_id: str):
    user_id = current_user_id_from_request()
    pid = parse_uuid(product_id)

    if user_id is None:
        return jsonify({"message": "Invalid user."}), 401
    if pid is None:
        return jsonify({"message": "Invalid product id."}), 400

    # Validate product exists first.
    product = db.session.get(Product, pid)
    if product is None:
        return jsonify({"message": "Product not found."}), 404

    existing = fetch_existing_like(user_id, pid)
    if existing is not None:
        return jsonify({"liked": True, "like": _serialize_like(existing, product=product)}), 200

    like = ProductLike()
    like.user_id = user_id
    like.product_id = pid
    db.session.add(like)

    try:
        db.session.commit()
    except IntegrityError:
        # Race-safe fallback: another request inserted the same row.
        db.session.rollback()
        existing = fetch_existing_like(user_id, pid)
        if existing is not None:
            return jsonify({"liked": True, "like": _serialize_like(existing, product=product)}), 200
        return jsonify({"message": "Could not save like."}), 500
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("POST /likes/<product_id> failed")
        return jsonify({"message": "Could not save like."}), 500

    return jsonify({"liked": True, "like": _serialize_like(like, product=product)}), 201


# ----------------------------------------------------------------------------
# Unlike product
# ----------------------------------------------------------------------------
@likes_bp.route("/likes/<product_id>", methods=["DELETE"])
@likes_bp.route("/product-likes/<product_id>", methods=["DELETE"])
@require_auth("customer")
def unlike_product(product_id: str):
    user_id = current_user_id_from_request()
    pid = parse_uuid(product_id)

    if user_id is None:
        return jsonify({"message": "Invalid user."}), 401
    if pid is None:
        return jsonify({"message": "Invalid product id."}), 400

    existing = fetch_existing_like(user_id, pid)
    if existing is None:
        return jsonify({"liked": False, "message": "Not liked."}), 200

    db.session.delete(existing)

    try:
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("DELETE /likes/<product_id> failed")
        return jsonify({"message": "Could not remove like."}), 500

    return jsonify({"liked": False, "message": "Unliked."}), 200


# ----------------------------------------------------------------------------
# Bulk sync likes (for localStorage -> DB migration)
# ----------------------------------------------------------------------------
@likes_bp.post("/likes/bulk-sync")
@likes_bp.post("/product-likes/bulk-sync")
@require_auth("customer")
def bulk_sync_likes():
    user_id = current_user_id_from_request()
    if user_id is None:
        return jsonify({"message": "Invalid user."}), 401

    body = request.get_json(silent=True)
    payload: Dict[str, Any] = body if isinstance(body, dict) else {}

    raw_ids = payload.get("product_ids", payload.get("productIds", []))
    replace = bool(payload.get("replace", False))

    if isinstance(raw_ids, str):
        raw_ids = [raw_ids]
    if not isinstance(raw_ids, list):
        raw_ids = []

    requested_ids = dedupe_uuid_list(raw_ids)

    # Safety cap
    if len(requested_ids) > 5000:
        return jsonify({"message": "Too many product IDs. Maximum is 5000."}), 400

    pk_col = _product_pk_col()
    if pk_col is None:
        return jsonify({"message": "Product schema misconfigured."}), 500

    # Keep only products that exist
    valid_ids: List[uuid.UUID] = []
    if requested_ids:
        valid_stmt = select(pk_col).where(pk_col.in_(requested_ids))
        valid_ids = list(db.session.execute(valid_stmt).scalars().all())

    # Optional replace semantics:
    # - replace=true + empty valid_ids => clear all likes for user
    # - replace=true + valid_ids       => keep only valid_ids
    if replace:
        if valid_ids:
            delete_stmt = (
                delete(ProductLike)
                .where(ProductLike.user_id == user_id)
                .where(ProductLike.product_id.notin_(valid_ids))
            )
        else:
            delete_stmt = delete(ProductLike).where(ProductLike.user_id == user_id)
        db.session.execute(delete_stmt)

    # Insert missing likes for valid IDs
    inserted = 0
    if valid_ids:
        existing_stmt = select(ProductLike.product_id).where(
            ProductLike.user_id == user_id,
            ProductLike.product_id.in_(valid_ids),
        )
        existing_ids = set(db.session.execute(existing_stmt).scalars().all())

        for pid in valid_ids:
            if pid in existing_ids:
                continue
            like = ProductLike()
            like.user_id = user_id
            like.product_id = pid
            db.session.add(like)
            inserted += 1

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        current_app.logger.exception("POST /likes/bulk-sync failed (IntegrityError)")
        return jsonify({"message": "Could not sync likes."}), 500
    except SQLAlchemyError:
        db.session.rollback()
        current_app.logger.exception("POST /likes/bulk-sync failed")
        return jsonify({"message": "Could not sync likes."}), 500

    # Return fresh full list (authoritative)
    total, rows = load_user_likes(user_id, limit=2000, offset=0)

    return jsonify(
        {
            "count": total,
            "synced_requested": len(requested_ids),
            "synced_valid": len(valid_ids),
            "inserted": inserted,
            "likes": [_serialize_like(like, product) for like, product in rows],
        }
    ), 200
