# ============================================================================
# backend/routes/public_marketplace.py — Lightweight Public Marketplace API
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Public, read-only marketplace summary for the StartScreen.
#
# WHY THIS FILE EXISTS:
#   The StartScreen should not depend on heavy product relationship loading.
#   This endpoint returns only the small public data needed by the homepage:
#     • categories
#     • featured products
#     • top products
#     • top farmers
#
# PERMANENT FIX:
#   ✅ One endpoint for the public homepage
#   ✅ No selectinload(Product.ratings)
#   ✅ No selectinload(Product.order_items)
#   ✅ Uses SQL aggregation instead of loading full relationships
#   ✅ Adds short in-memory cache to reduce repeated DB work
#   ✅ Keeps login independent from marketplace loading
#
# IMPORTANT TYPE-CHECKER FIX:
#   Some editors/Pyright setups complain about:
#     from flask import Blueprint, request
#     import flask; flask.Blueprint / flask.request
#
#   Therefore this file imports from Flask's typed submodules:
#     from flask.blueprints import Blueprint
#     from flask.globals import request
#
#   JSON responses are created with werkzeug.wrappers.Response to avoid
#   any jsonify import-symbol issues.
# ============================================================================

from __future__ import annotations

import json
import logging
import time
from datetime import datetime
from decimal import Decimal
from typing import Any, Optional
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from sqlalchemy import desc, func, select
from werkzeug.wrappers import Response

from backend.database.db import db
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.rating import Rating
from backend.models.user import ROLE_FARMER, User
from backend.utils.upload_utils import default_image_url


# ----------------------------------------------------------------------------
# Blueprint
# ----------------------------------------------------------------------------
public_marketplace_bp = Blueprint("public_marketplace", __name__)

logger = logging.getLogger("backend.routes.public_marketplace")


# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
_PUBLIC_STATUSES = {"available", "approved", "active", "published"}

_CACHE_TTL_SECONDS = 120
_CACHE: dict[str, Any] = {
    "expires_at": 0.0,
    "payload": None,
}


# ----------------------------------------------------------------------------
# JSON response helper
# ----------------------------------------------------------------------------
def _json_response(payload: dict[str, Any], status: int = 200) -> Response:
    """
    Return a JSON HTTP response without relying on flask.jsonify.

    This avoids editor/type-checker complaints in environments where Flask's
    re-exported helpers are not detected correctly.
    """
    return Response(
        json.dumps(payload, default=str),
        status=status,
        mimetype="application/json",
    )


# ----------------------------------------------------------------------------
# Small defensive helpers
# ----------------------------------------------------------------------------
def _to_int(value: Any, default: int) -> int:
    """Safely convert a value to int."""
    try:
        raw = str(value).strip()
        return int(raw) if raw else default
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert DB numeric values, including Decimal, to float."""
    try:
        if value is None:
            return default
        if isinstance(value, Decimal):
            return float(value)
        return float(value)
    except Exception:
        return default


def _safe_str(value: Any, default: str = "") -> str:
    """Safely convert any value to a trimmed string."""
    try:
        text = str(value or "").strip()
        return text or default
    except Exception:
        return default


def _uuid_text(value: Any) -> str:
    """Return UUID values as strings for JSON responses."""
    if isinstance(value, UUID):
        return str(value)
    return _safe_str(value)


def _dt_iso(value: Any) -> Optional[str]:
    """Return datetime values as ISO strings."""
    if isinstance(value, datetime):
        return value.isoformat()
    return None


def _image_url(value: Any) -> str:
    """Return product image URL or default placeholder."""
    text = _safe_str(value)
    return text or default_image_url()


def _canonical_category(value: Any) -> str:
    """Normalize empty categories to Other."""
    text = _safe_str(value, "Other")
    return text if text else "Other"


# ----------------------------------------------------------------------------
# Payload builders
# ----------------------------------------------------------------------------
def _product_payload(
    product: Product,
    *,
    farmer_name: str,
    farmer_location: str,
    rating_count: int,
    avg_rating: float,
    order_count: int,
    sold_quantity: float,
) -> dict[str, Any]:
    """
    Convert one product row into the compact public product format.

    Important:
      This does not access heavy relationships like product.ratings or
      product.order_items. Counts are already calculated through SQL aggregates.
    """
    product_id = _uuid_text(getattr(product, "product_id", None))
    farmer_id = _uuid_text(getattr(product, "user_id", None))
    name = _safe_str(getattr(product, "product_name", None), "Product")
    category = _canonical_category(getattr(product, "category", None))
    image = _image_url(getattr(product, "image_url", None))
    stock = _safe_float(getattr(product, "quantity", 0), 0.0)
    price = _safe_float(getattr(product, "price", 0), 0.0)

    # Lightweight ranking score for homepage ordering.
    score = round(
        (sold_quantity * 3.0)
        + (avg_rating * 14.0)
        + (rating_count * 2.0)
        + (stock * 0.08),
        3,
    )

    return {
        "id": product_id,
        "product_id": product_id,
        "name": name,
        "product_name": name,
        "description": _safe_str(getattr(product, "description", None)),
        "category": category,
        "price": price,
        "quantity": stock,
        "stock": stock,
        "unit": _safe_str(getattr(product, "unit", None), "each"),
        "status": _safe_str(getattr(product, "status", None), "available"),
        "image_url": image,
        "imageUrl": image,
        "farmer_id": farmer_id,
        "user_id": farmer_id,
        "farmer_name": farmer_name,
        "farmer_location": farmer_location,
        "location": farmer_location,
        "rating_count": rating_count,
        "avg_rating": round(avg_rating, 2),
        "order_count": order_count,
        "sold_quantity": round(sold_quantity, 3),
        "homepage_score": score,
        "featured_score": score,
        "created_at": _dt_iso(getattr(product, "created_at", None)),
        "cta_label": "Register to buy",
        "gate_action": "register_to_buy",
    }


def _empty_payload() -> dict[str, Any]:
    """Consistent empty response so the frontend does not crash."""
    return {
        "success": True,
        "source": "public_marketplace_summary",
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_public_products": 0,
            "total_categories": 0,
            "total_public_farmers": 0,
            "featured_count": 0,
        },
        "categories": [],
        "featured_products": [],
        "top_products": [],
        "top_farmers": [],
        "latest_products": [],
        "sections": {
            "categories": [],
            "featured_products": [],
            "top_products": [],
            "top_farmers": [],
            "latest_products": [],
        },
    }


def _build_categories(products: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Build category summary cards from compact product rows."""
    buckets: dict[str, dict[str, Any]] = {}

    for product in products:
        category = _canonical_category(product.get("category"))

        bucket = buckets.setdefault(
            category,
            {
                "category": category,
                "count": 0,
                "product_count": 0,
                "image_url": product.get("image_url") or default_image_url(),
                "preview_names": [],
                "tagline": f"Browse {category.lower()} products from local farmers.",
            },
        )

        bucket["count"] += 1
        bucket["product_count"] += 1

        name = _safe_str(product.get("name") or product.get("product_name"))
        if name and name not in bucket["preview_names"] and len(bucket["preview_names"]) < 3:
            bucket["preview_names"].append(name)

    rows = list(buckets.values())
    rows.sort(key=lambda row: (-int(row.get("count", 0)), str(row.get("category", ""))))

    return rows[:limit]


def _build_top_farmers(products: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    """Build farmer summary cards from compact product rows."""
    farmers: dict[str, dict[str, Any]] = {}

    for product in products:
        farmer_id = _safe_str(product.get("farmer_id") or product.get("user_id"))
        if not farmer_id:
            continue

        bucket = farmers.setdefault(
            farmer_id,
            {
                "farmer_id": farmer_id,
                "farmer_name": _safe_str(product.get("farmer_name"), "Farmer"),
                "location": _safe_str(product.get("farmer_location") or product.get("location")),
                "product_count": 0,
                "category_names": set(),
                "product_names": [],
                "total_stock": 0.0,
                "total_orders": 0,
                "sold_quantity": 0.0,
                "rating_weighted_sum": 0.0,
                "rating_count": 0,
                "score": 0.0,
                "hero_image_candidates": [],
            },
        )

        bucket["product_count"] += 1
        bucket["category_names"].add(_canonical_category(product.get("category")))
        bucket["total_stock"] += _safe_float(product.get("stock") or product.get("quantity"), 0.0)
        bucket["total_orders"] += int(_safe_float(product.get("order_count"), 0.0))
        bucket["sold_quantity"] += _safe_float(product.get("sold_quantity"), 0.0)
        bucket["score"] += _safe_float(product.get("homepage_score"), 0.0)

        rating_count = int(_safe_float(product.get("rating_count"), 0.0))
        avg_rating = _safe_float(product.get("avg_rating"), 0.0)
        bucket["rating_weighted_sum"] += avg_rating * rating_count
        bucket["rating_count"] += rating_count

        name = _safe_str(product.get("name") or product.get("product_name"))
        if name and name not in bucket["product_names"] and len(bucket["product_names"]) < 3:
            bucket["product_names"].append(name)

        image = _safe_str(product.get("image_url"))
        if image and image not in bucket["hero_image_candidates"]:
            bucket["hero_image_candidates"].append(image)

    out: list[dict[str, Any]] = []

    for farmer in farmers.values():
        rating_count = int(farmer["rating_count"] or 0)
        avg_rating = (
            round(float(farmer["rating_weighted_sum"]) / rating_count, 2)
            if rating_count
            else 0.0
        )

        candidates = list(farmer.get("hero_image_candidates") or [])[:6]
        hero = candidates[0] if candidates else default_image_url()

        out.append(
            {
                "farmer_id": farmer["farmer_id"],
                "farmer_name": farmer["farmer_name"],
                "location": farmer["location"],
                "product_count": farmer["product_count"],
                "category_count": len(farmer["category_names"]),
                "featured_categories": sorted(farmer["category_names"])[:3],
                "top_product_names": farmer["product_names"],
                "total_stock": round(float(farmer["total_stock"]), 2),
                "total_orders": farmer["total_orders"],
                "sold_quantity": round(float(farmer["sold_quantity"]), 3),
                "rating_count": rating_count,
                "avg_rating": avg_rating,
                "score": round(float(farmer["score"]), 3),
                "image_url": hero,
                "avatar_url": hero,
                "hero_image_url": hero,
                "hero_image_candidates": candidates,
                "cta_label": "Register to sell",
                "gate_action": "register_to_sell",
            }
        )

    out.sort(
        key=lambda row: (
            -_safe_float(row.get("score"), 0.0),
            -int(row.get("product_count", 0)),
            -_safe_float(row.get("avg_rating"), 0.0),
            str(row.get("farmer_name", "")),
        )
    )

    return out[:limit]


# ----------------------------------------------------------------------------
# Main data loader
# ----------------------------------------------------------------------------
def _load_payload() -> dict[str, Any]:
    """
    Load public marketplace data using one compact query.

    This avoids relationship loading and keeps the homepage fast.
    """
    args = request.args

    category_limit = max(1, min(_to_int(args.get("category_limit"), 8), 12))
    featured_limit = max(1, min(_to_int(args.get("featured_limit"), 6), 12))
    top_products_limit = max(1, min(_to_int(args.get("top_products_limit"), 8), 12))
    top_farmers_limit = max(1, min(_to_int(args.get("top_farmers_limit"), 6), 10))
    latest_limit = max(1, min(_to_int(args.get("latest_limit"), 12), 24))
    scan_limit = max(24, min(_to_int(args.get("scan_limit"), 180), 300))

    # Rating aggregation subquery.
    rating_sq = (
        select(
            Rating.product_id.label("product_id"),
            func.count(Rating.id).label("rating_count"),
            func.coalesce(func.avg(Rating.rating_score), 0).label("avg_rating"),
        )
        .group_by(Rating.product_id)
        .subquery()
    )

    # Order aggregation subquery.
    order_sq = (
        select(
            OrderItem.product_id.label("product_id"),
            func.count(func.distinct(OrderItem.order_id)).label("order_count"),
            func.coalesce(func.sum(OrderItem.quantity), 0).label("sold_quantity"),
        )
        .group_by(OrderItem.product_id)
        .subquery()
    )

    # Compact public product query.
    stmt = (
        select(
            Product,
            User.full_name.label("farmer_name"),
            User.location.label("farmer_location"),
            func.coalesce(rating_sq.c.rating_count, 0).label("rating_count"),
            func.coalesce(rating_sq.c.avg_rating, 0).label("avg_rating"),
            func.coalesce(order_sq.c.order_count, 0).label("order_count"),
            func.coalesce(order_sq.c.sold_quantity, 0).label("sold_quantity"),
        )
        .join(User, User.id == Product.user_id, isouter=True)
        .join(rating_sq, rating_sq.c.product_id == Product.product_id, isouter=True)
        .join(order_sq, order_sq.c.product_id == Product.product_id, isouter=True)
        .where(Product.status.in_(sorted(_PUBLIC_STATUSES)))
        .where((User.role == ROLE_FARMER) | (User.role.is_(None)))
        .order_by(desc(Product.created_at))
        .limit(scan_limit)
    )

    rows = db.session.execute(stmt).all()

    products: list[dict[str, Any]] = []

    for row in rows:
        product = row[0]

        products.append(
            _product_payload(
                product,
                farmer_name=_safe_str(row.farmer_name, "Farmer"),
                farmer_location=_safe_str(row.farmer_location),
                rating_count=int(_safe_float(row.rating_count, 0.0)),
                avg_rating=_safe_float(row.avg_rating, 0.0),
                order_count=int(_safe_float(row.order_count, 0.0)),
                sold_quantity=_safe_float(row.sold_quantity, 0.0),
            )
        )

    if not products:
        return _empty_payload()

    latest_products = products[:latest_limit]

    featured_products = sorted(
        products,
        key=lambda row: (
            -_safe_float(row.get("featured_score"), 0.0),
            -_safe_float(row.get("avg_rating"), 0.0),
            str(row.get("created_at") or ""),
        ),
    )[:featured_limit]

    top_products = sorted(
        products,
        key=lambda row: (
            -_safe_float(row.get("homepage_score"), 0.0),
            -_safe_float(row.get("order_count"), 0.0),
            -_safe_float(row.get("avg_rating"), 0.0),
            str(row.get("created_at") or ""),
        ),
    )[:top_products_limit]

    categories = _build_categories(products, category_limit)
    top_farmers = _build_top_farmers(products, top_farmers_limit)

    unique_farmers = {
        _safe_str(product.get("farmer_id") or product.get("user_id"))
        for product in products
        if _safe_str(product.get("farmer_id") or product.get("user_id"))
    }

    unique_categories = {
        _canonical_category(product.get("category"))
        for product in products
        if _canonical_category(product.get("category"))
    }

    return {
        "success": True,
        "source": "public_marketplace_summary",
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_public_products": len(products),
            "total_categories": len(unique_categories),
            "total_public_farmers": len(unique_farmers),
            "featured_count": len(featured_products),
        },
        "categories": categories,
        "featured_products": featured_products,
        "top_products": top_products,
        "top_farmers": top_farmers,
        "latest_products": latest_products,
        "sections": {
            "categories": categories,
            "featured_products": featured_products,
            "top_products": top_products,
            "top_farmers": top_farmers,
            "latest_products": latest_products,
        },
    }


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
@public_marketplace_bp.get("/marketplace-summary", strict_slashes=False)
def marketplace_summary() -> Response:
    """
    Public homepage endpoint.

    Final URL:
      GET /api/public/marketplace-summary

    Optional:
      ?refresh=1

    Use refresh=1 during testing to bypass the in-memory cache.
    """
    refresh = str(request.args.get("refresh") or "").lower() in {
        "1",
        "true",
        "yes",
    }

    now = time.time()

    if not refresh and _CACHE["payload"] is not None and now < float(_CACHE["expires_at"]):
        return _json_response(_CACHE["payload"])

    started = time.perf_counter()

    try:
        payload = _load_payload()

        _CACHE["payload"] = payload
        _CACHE["expires_at"] = now + _CACHE_TTL_SECONDS

        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        logger.info("public marketplace summary loaded in %sms", elapsed_ms)

        return _json_response(payload)

    except Exception as exc:
        logger.exception("Failed to load public marketplace summary: %s", exc)

        response = _empty_payload()
        response["success"] = False
        response["message"] = "Could not load public marketplace summary."

        return _json_response(response, status=500)