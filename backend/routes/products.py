# ====================================================================
# backend/routes/products.py — Product Management API (JWT-PROTECTED where needed)
# ====================================================================
# FILE ROLE:
#   Product CRUD + marketplace listing for AgroConnect Namibia.
#   • Public marketplace listing (no auth required)
#   • Farmer dashboard listing via OPTIONAL JWT (GET /products?farmerId=<id>)
#   • Farmer/Admin create/update/delete
#
# APPROVAL WORKFLOW (OPTION 1):
#   • Farmer-created products default to status="pending"
#   • Marketplace shows ONLY statuses in _PUBLIC_STATUSES
#   • Admin moderation routes handled by: backend/routes/admin_products.py
#
# KEY FIXES IN THIS VERSION:
#   ✅ Optional JWT verification for GET /products (public stays public)
#   ✅ imageUrl alias included for frontend compatibility
#   ✅ Image URL normalization for absolute/root/filename cases
#   ✅ Includes location info (farmer_location + location) in responses
#   ✅ Robust filtering + sorting + pagination helpers
#   ✅ Admin moderation-safe updates + snapshot refresh on approval
#   ✅ /products/new now returns ONLY genuinely recent products
#      (default: last 7 days, configurable via ?days=7)
#
# UNIT NORMALIZATION FIX:
#   ✅ Normalizes legacy / UI-friendly unit aliases into canonical DB units:
#        piece/items -> each
#        litre/liter -> l
#        box/crate/bag/tray/packet -> pack
#   ✅ Keeps DB-safe canonical units only:
#        kg, g, l, ml, each, pack
#   ✅ Gives clearer validation message when a pack is missing pack_size/pack_unit
#   ✅ Keeps pack rules academically clean:
#        - price = price per pack
#        - quantity = number of packs in stock
#        - pack_size + pack_unit describe what one pack contains
#
# NOTIFICATION FIX (THIS UPDATE):
#   ✅ Replaces direct `n.type = ...` assignment
#   ✅ Uses schema-aligned `notification_type`
#   ✅ Uses _maybe_set(...) for optional model fields to avoid Pylance errors
#   ✅ Keeps backward compatibility with older notification model variants
#
# PYRIGHT FIX (THIS UPDATE):
#   ✅ Removes `EllipsisType` default values from TYPE_CHECKING Flask stubs
#   ✅ Uses real bool defaults in Blueprint decorator signatures
# ====================================================================

from __future__ import annotations

import re
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Mapping, Optional, TYPE_CHECKING, TypeVar
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import selectinload

from backend.database.db import db
from backend.models.product import Product
from backend.models.user import ROLE_ADMIN, ROLE_FARMER, User
from backend.utils.require_auth import (
    AuthError,
    require_access_token,
    verify_access_from_request,
)
from backend.utils.upload_utils import default_image_url, save_image

# --------------------------------------------------------------------
# Optional Notification/SMS/Email integrations (best-effort only)
# --------------------------------------------------------------------
Notification = None
send_sms = None
send_email = None

try:  # pragma: no cover
    from backend.models.notification import Notification as _Notification  # type: ignore

    Notification = _Notification
except Exception:
    Notification = None

try:  # pragma: no cover
    from backend.utils.sms_utils import send_sms as _send_sms  # type: ignore

    send_sms = _send_sms
except Exception:
    send_sms = None

try:  # pragma: no cover
    from backend.utils.email_utils import send_email as _send_email  # type: ignore

    send_email = _send_email
except Exception:
    send_email = None

# --------------------------------------------------------------------
# Flask symbols (runtime import) + type-check helpers
# --------------------------------------------------------------------
F = TypeVar("F", bound=Callable[..., Any])

if TYPE_CHECKING:
    from flask import Request as FlaskRequest  # type: ignore

    request: FlaskRequest

    def jsonify(*args: Any, **kwargs: Any) -> Any: ...

    class Blueprint:
        def __init__(self, name: str, import_name: str) -> None: ...

        # IMPORTANT:
        # Use real bool defaults here. Using `...` causes Pyright to infer
        # EllipsisType, which then triggers:
        #   "Expression of type 'EllipsisType' cannot be assigned to parameter of type 'bool'"
        def get(self, rule: str, strict_slashes: bool = False) -> Callable[[F], F]: ...
        def post(self, rule: str, strict_slashes: bool = False) -> Callable[[F], F]: ...
        def put(self, rule: str, strict_slashes: bool = False) -> Callable[[F], F]: ...
        def delete(self, rule: str, strict_slashes: bool = False) -> Callable[[F], F]: ...
        def route(
            self,
            rule: str,
            methods: list[str] | tuple[str, ...],
            strict_slashes: bool = False,
        ) -> Callable[[F], F]: ...
else:
    from flask import Blueprint, jsonify, request  # type: ignore[assignment]

# --------------------------------------------------------------------
# Blueprint
# --------------------------------------------------------------------
products_bp = Blueprint("products", __name__)

# Canonical DB-safe selling units
_ALLOWED_UNITS = {"kg", "g", "l", "ml", "each", "pack"}

# Valid content units for a single pack
_ALLOWED_PACK_UNITS = {"kg", "g", "l", "ml", "each"}

# Legacy / UI-friendly aliases that should be normalized into the canonical DB
# values before validation.
#
# IMPORTANT:
#   The database does NOT allow "box", "crate", or "bag" as real unit values.
#   We normalize those to "pack" here so older frontend payloads do not fail
#   with a confusing "Invalid unit" error.
_UNIT_ALIASES: dict[str, str] = {
    "piece": "each",
    "pieces": "each",
    "item": "each",
    "items": "each",
    "unit": "each",
    "litre": "l",
    "litres": "l",
    "liter": "l",
    "liters": "l",
    "box": "pack",
    "crate": "pack",
    "bag": "pack",
    "tray": "pack",
    "packet": "pack",
    "packets": "pack",
}

_PUBLIC_STATUSES = {"available", "approved", "active", "published"}
_ALLOWED_STATUSES = {
    "pending",
    "approved",
    "rejected",
    "available",
    "unavailable",
    "active",
    "published",
}

TOP_CATEGORIES = [
    "Fresh Produce",
    "Animal Products",
    "Fish & Seafood",
    "Staples",
    "Nuts, Seeds & Oils",
    "Honey & Sweeteners",
    "Value-Added & Processed (Farm-made)",
    "Farm Supplies",
    "Wild Harvest",
]
_TOP_CATEGORIES_LOWER = {c.lower(): c for c in TOP_CATEGORIES}

# --------------------------------------------------------------------
# New-products feed configuration
# --------------------------------------------------------------------
_DEFAULT_NEW_PRODUCT_DAYS = 7
_MAX_NEW_PRODUCT_DAYS = 30


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------
def _json_error(message: str, status: int) -> Any:
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


def _to_uuid(value: Any) -> Optional[UUID]:
    try:
        return UUID(str(value))
    except Exception:
        return None


def _to_int(value: Any, default: int) -> int:
    try:
        raw = str(value).strip()
        if not raw:
            return default
        return int(raw)
    except Exception:
        return default


def _to_decimal(value: Any, default: Decimal) -> Decimal:
    try:
        raw = str(value).strip()
        if not raw:
            return default
        return Decimal(raw)
    except (InvalidOperation, ValueError):
        return default


def _to_qty_decimal(value: Any, default: Decimal) -> Decimal:
    d = _to_decimal(value, default)
    try:
        return d.quantize(Decimal("0.001"))
    except Exception:
        return default


def _to_money_decimal(value: Any, default: Decimal) -> Decimal:
    d = _to_decimal(value, default)
    try:
        return d.quantize(Decimal("0.01"))
    except Exception:
        return default


def _clean_unit(value: Any, default: str = "each") -> str:
    """
    Normalize incoming unit text into a canonical DB-safe unit.

    Examples:
      - "BOX"   -> "pack"
      - "bag"   -> "pack"
      - "piece" -> "each"
      - "litre" -> "l"

    IMPORTANT:
      - Blank input falls back to the provided default.
      - Unknown non-blank input is preserved so validation can reject it clearly.
    """
    raw = str(value or "").strip().lower()
    if not raw:
        return default
    return _UNIT_ALIASES.get(raw, raw)


def _payload() -> dict[str, Any]:
    js = request.get_json(silent=True)
    if isinstance(js, dict):
        return js
    return dict(request.form or {})


def _maybe_set(obj: Any, attr: str, value: Any) -> None:
    """
    Best-effort setattr wrapper.

    Why this exists:
      - Some optional models are imported dynamically.
      - Not every deployment has every column/field.
      - Using _maybe_set avoids direct unknown-attribute assignments that static
        type checkers dislike and keeps the code resilient across schema variants.
    """
    try:
        if hasattr(obj, attr):
            setattr(obj, attr, value)
    except Exception:
        return


def _maybe_get(obj: Any, attr: str, default: Any = None) -> Any:
    try:
        return getattr(obj, attr, default) if hasattr(obj, attr) else default
    except Exception:
        return default


def _current_user() -> Optional[User]:
    u = getattr(request, "current_user", None)
    return u if isinstance(u, User) else None


def _maybe_auth_user() -> tuple[Optional[User], Optional[Any]]:
    """
    Optional auth:
      - If Authorization header exists, verify it and inject request.current_user
      - If no Authorization, stay public
    """
    already = _current_user()
    if already is not None:
        return already, None

    auth = (request.headers.get("Authorization") or "").strip()
    if not auth:
        return None, None

    try:
        u = verify_access_from_request(request)  # injects request.current_user
        return u, None
    except AuthError as exc:
        return None, _json_error(str(exc), exc.status_code)
    except Exception:
        return None, _json_error("Unauthorized", 401)


def _owner_id(product: Product) -> Any:
    return getattr(product, "user_id", None) or getattr(product, "farmer_id", None)


def _set_owner(product: Product, user_id: Any) -> None:
    if hasattr(product, "user_id"):
        setattr(product, "user_id", user_id)
    else:
        setattr(product, "farmer_id", user_id)


def _owner_fk_column() -> Any:
    col = getattr(Product, "user_id", None)
    return col if col is not None else getattr(Product, "farmer_id")


def _pk_column() -> Any:
    col = getattr(Product, "product_id", None)
    return col if col is not None else getattr(Product, "id")


def _created_at_column() -> Any:
    """
    Prefer created_at when available.

    Fallback to primary key only for generic sorting compatibility elsewhere.
    Important:
      /products/new will not rely on the PK fallback for freshness filtering.
      It will only apply a true time filter when a real created_at column exists.
    """
    col = getattr(Product, "created_at", None)
    return col if col is not None else _pk_column()


def _canonical_category(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "Fresh Produce"
    hit = _TOP_CATEGORIES_LOWER.get(raw.lower())
    if hit:
        return hit

    s = raw.lower()
    if any(k in s for k in ["wild", "!nara", "mopane", "mushroom", "veld"]):
        return "Wild Harvest"
    if any(
        k in s
        for k in [
            "feed",
            "lucerne",
            "hay",
            "seedling",
            "nursery",
            "fertil",
            "pesticide",
            "supplies",
        ]
    ):
        return "Farm Supplies"
    if any(k in s for k in ["honey", "sweetener", "syrup", "beeswax"]):
        return "Honey & Sweeteners"
    if any(k in s for k in ["fish", "seafood", "hake", "tilapia", "oyster", "prawn", "shrimp"]):
        return "Fish & Seafood"
    if any(k in s for k in ["nut", "seed", "groundnut", "peanut", "sunflower", "sesame", "oil"]):
        return "Nuts, Seeds & Oils"
    if any(k in s for k in ["mahangu", "maize", "sorghum", "rice", "wheat", "bean", "cowpea", "lentil"]):
        return "Staples"
    if any(k in s for k in ["milk", "dairy", "omaere", "yoghurt", "cheese", "egg", "meat", "beef", "chicken"]):
        return "Animal Products"
    if any(k in s for k in ["processed", "farm-made", "flour", "jam", "pickle", "chutney", "biltong"]):
        return "Value-Added & Processed (Farm-made)"

    return "Fresh Produce"


def _normalize_image_url_or_filename(raw_value: Any) -> str:
    """
    Normalize image references to stable, frontend-safe values:
    - keep absolute URLs as-is
    - normalize generic / missing defaults to the bundled product placeholder
    - normalize upload paths to the backend-served /api/uploads/... form
    - keep frontend public asset paths rooted under /Assets/...
    - map bare filenames to /api/uploads/products/<file>
    - map relative paths to rooted canonical paths
    """
    raw = str(raw_value or "").strip()
    if not raw:
        return ""

    raw = raw.replace("\\", "/")
    lowered = raw.lower()

    if re.match(r"^(https?:)?//", raw, flags=re.IGNORECASE):
        return raw
    if lowered.startswith("data:") or lowered.startswith("blob:"):
        return raw

    default_markers = (
        "default.jpg",
        "default.jpeg",
        "default.png",
        "default-product",
        "/defaults/",
        "/uploads/defaults/",
        "/api/uploads/defaults/",
        "/uploads/product_images/default",
        "/api/uploads/product_images/default",
        "placeholder",
        "no-image",
        "no_image",
        "noimage",
    )
    if any(marker in lowered for marker in default_markers):
        return "/Assets/product_images/default.jpg"

    if raw.startswith("/"):
        clean_rel = raw.lstrip("/").replace("\\", "/")
        if clean_rel.lower().startswith("uploads/"):
            return f"/api/{clean_rel}"
        if clean_rel.lower().startswith("api/uploads/"):
            return f"/{clean_rel}"
        if clean_rel.lower().startswith("assets/"):
            return f"/{clean_rel}".replace("/assets/", "/Assets/", 1)
        return f"/{clean_rel}"

    clean = raw.replace("\\", "/").strip("/")
    lower_clean = clean.lower()
    if "/" not in clean:
        return f"/api/uploads/products/{clean}"
    if lower_clean.startswith("uploads/"):
        return f"/api/{clean}"
    if lower_clean.startswith("api/uploads/"):
        return f"/{clean}"
    if lower_clean.startswith("assets/"):
        return f"/{clean}".replace("/assets/", "/Assets/", 1)
    return f"/{clean}"

def _is_defaultish_image_url(raw_value: Any) -> bool:
    """
    Detect placeholder / generic product images.

    Why this matters for the homepage top-farmers shelf:
      - A farmer should preferably get a real product image as their hero artwork.
      - The shared default product placeholder should not win too early.
    """
    raw = str(raw_value or "").strip().replace("\\", "/").lower()
    if not raw:
        return True

    markers = (
        "default.jpg",
        "default.jpeg",
        "default.png",
        "default-product",
        "/defaults/",
        "/uploads/defaults/",
        "/api/uploads/defaults/",
        "/uploads/product_images/default",
        "/api/uploads/product_images/default",
        "placeholder",
        "no-image",
        "no_image",
        "noimage",
    )
    return any(marker in raw for marker in markers)


def _append_unique_image_candidate(bucket: list[str], raw_value: Any) -> None:
    """
    Add a normalized image candidate once, skipping blank/default-ish values.
    """
    candidate = _normalize_image_url_or_filename(raw_value)
    if not candidate or _is_defaultish_image_url(candidate):
        return
    if candidate not in bucket:
        bucket.append(candidate)


def _apply_c1_unit_fields(product: Product, data: Mapping[str, Any]) -> Optional[Any]:
    """
    Canonical selling-unit rules:
      - each: sold per single item
      - kg/g/l/ml: sold per selected measure unit
      - pack: sold per pack, requires pack_size + pack_unit

    IMPORTANT:
      quantity is stock available in the chosen selling unit.
      Examples:
        unit='kg'   -> quantity is kg in stock
        unit='each' -> quantity is item count in stock
        unit='pack' -> quantity is number of packs in stock
    """
    unit = _clean_unit(data.get("unit", getattr(product, "unit", "each")), default="each")

    if unit not in _ALLOWED_UNITS:
        return _json_error(
            f"Invalid unit. Allowed: {sorted(_ALLOWED_UNITS)}",
            400,
        )

    _maybe_set(product, "unit", unit)

    if unit == "pack":
        pack_size = _to_qty_decimal(data.get("pack_size"), Decimal("0.000"))
        pack_unit = _clean_unit(data.get("pack_unit"), default="")

        if pack_size <= 0:
            return _json_error(
                "When unit='pack', you must provide pack_size > 0. Example: 250 g pack -> unit='pack', pack_size=250, pack_unit='g'.",
                400,
            )

        if pack_unit not in _ALLOWED_PACK_UNITS:
            return _json_error(
                f"pack_unit must be one of {sorted(_ALLOWED_PACK_UNITS)}",
                400,
            )

        _maybe_set(product, "pack_size", pack_size)
        _maybe_set(product, "pack_unit", pack_unit)
    else:
        _maybe_set(product, "pack_size", None)
        _maybe_set(product, "pack_unit", None)

    return None


def _serialize_product(
    product: Product,
    farmer_name: str | None = None,
    farmer_location: str | None = None,
    include_moderation: bool = False,
) -> dict[str, Any]:
    base: dict[str, Any] = dict(product.to_dict()) if hasattr(product, "to_dict") else {}

    pid = (
        base.get("id")
        or base.get("product_id")
        or getattr(product, "id", None)
        or getattr(product, "product_id", None)
    )
    base["id"] = str(pid) if pid else None
    base["product_id"] = str(pid) if pid else None

    owner = base.get("user_id") or base.get("farmer_id") or _owner_id(product)
    base["user_id"] = str(owner) if owner else None
    base["farmer_id"] = str(owner) if owner else None

    pname = base.get("product_name") or getattr(product, "product_name", None) or base.get("name")
    base["product_name"] = pname
    base["name"] = pname

    img = base.get("image_url") or getattr(product, "image_url", None)
    img = _normalize_image_url_or_filename(img) if img else default_image_url()
    base["image_url"] = img
    base["imageUrl"] = img

    try:
        base["price"] = float(getattr(product, "price", base.get("price", 0)) or 0)
    except Exception:
        base["price"] = 0.0

    try:
        qty_val = getattr(product, "quantity", base.get("quantity", 0)) or 0
        base["quantity"] = float(qty_val)
    except Exception:
        base["quantity"] = 0.0

    base["stock"] = base["quantity"]

    if hasattr(product, "unit"):
        base["unit"] = _clean_unit(getattr(product, "unit"), default="each")
    if hasattr(product, "pack_size"):
        ps = getattr(product, "pack_size", None)
        base["pack_size"] = float(ps) if ps is not None else None
    if hasattr(product, "pack_unit"):
        pu = getattr(product, "pack_unit", None)
        base["pack_unit"] = _clean_unit(pu, default="") if pu else None

    if farmer_name is not None:
        base["farmer_name"] = farmer_name
    if farmer_location is not None:
        base["farmer_location"] = farmer_location
        base["location"] = farmer_location

    base["category"] = _canonical_category(base.get("category"))

    if include_moderation:
        base["status"] = str(getattr(product, "status", "") or "")
        base["rejection_reason"] = _maybe_get(product, "rejection_reason", None)

        rb = _maybe_get(product, "reviewed_by", None)
        base["reviewed_by"] = str(rb) if rb else None

        ra = _maybe_get(product, "reviewed_at", None)
        base["reviewed_at"] = ra.isoformat() if isinstance(ra, datetime) else None

        sa = _maybe_get(product, "submitted_at", None)
        base["submitted_at"] = sa.isoformat() if isinstance(sa, datetime) else None

        su = _maybe_get(product, "status_updated_at", None)
        base["status_updated_at"] = su.isoformat() if isinstance(su, datetime) else None

        base["moderation_snapshot"] = _maybe_get(product, "moderation_snapshot", None)
        base["moderation_changes"] = _maybe_get(product, "moderation_changes", None)

    return base


def _wrap_products(items: list[dict[str, Any]]) -> Any:
    return jsonify({"products": items, "count": len(items)})


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _category_tagline(category: str) -> str:
    mapping = {
        "Fresh Produce": "Seasonal fruits and vegetables from local farms.",
        "Animal Products": "Meat, dairy, eggs, and other livestock-based goods.",
        "Fish & Seafood": "Fresh and value-added aquatic produce for the market.",
        "Staples": "Daily food essentials such as grains, beans, and cereals.",
        "Nuts, Seeds & Oils": "Oil crops, edible seeds, and nutrition-rich produce.",
        "Honey & Sweeteners": "Natural sweeteners and hive-based farm products.",
        "Value-Added & Processed (Farm-made)": "Farm-made products packaged for ready sale.",
        "Farm Supplies": "Seedlings, feed, inputs, and practical farm essentials.",
        "Wild Harvest": "Traditional and naturally harvested Namibian products.",
    }
    return mapping.get(category, "Browse products from verified AgroConnect farmers.")


def _product_metrics(product: Product) -> dict[str, Any]:
    ratings = list(getattr(product, "ratings", []) or [])
    rating_values = [
        _safe_float(getattr(r, "rating_score", None), 0.0)
        for r in ratings
        if _safe_float(getattr(r, "rating_score", None), 0.0) > 0
    ]
    rating_count = len(rating_values)
    avg_rating = round(sum(rating_values) / rating_count, 2) if rating_count else 0.0

    order_items = list(getattr(product, "order_items", []) or [])
    order_ids = {str(getattr(item, "order_id", "")) for item in order_items if getattr(item, "order_id", None)}
    order_count = len(order_ids) if order_ids else len(order_items)
    sold_quantity = round(
        sum(_safe_float(getattr(item, "quantity", None), 0.0) for item in order_items),
        3,
    )

    created_at = getattr(product, "created_at", None)
    age_days = 365.0
    if isinstance(created_at, datetime):
        age_days = max(0.0, (datetime.utcnow() - created_at).total_seconds() / 86400.0)

    freshness_bonus = max(0.0, 14.0 - min(age_days, 14.0))
    stock = _safe_float(getattr(product, "quantity", None), 0.0)

    featured_score = round(
        (order_count * 8.0)
        + (sold_quantity * 2.5)
        + (avg_rating * 12.0)
        + (rating_count * 1.5)
        + freshness_bonus
        + (2.0 if stock > 0 else 0.0),
        3,
    )
    top_score = round(
        (order_count * 10.0)
        + (sold_quantity * 3.0)
        + (avg_rating * 14.0)
        + (rating_count * 2.0)
        + (stock * 0.08),
        3,
    )

    return {
        "rating_count": rating_count,
        "avg_rating": avg_rating,
        "order_count": order_count,
        "sold_quantity": sold_quantity,
        "age_days": round(age_days, 2),
        "featured_score": featured_score,
        "top_score": top_score,
    }


def _serialize_homepage_product(
    product: Product,
    farmer_name: str | None = None,
    farmer_location: str | None = None,
) -> dict[str, Any]:
    payload = _serialize_product(
        product,
        farmer_name=farmer_name,
        farmer_location=farmer_location,
        include_moderation=False,
    )
    metrics = _product_metrics(product)

    payload.update(
        {
            "rating_count": metrics["rating_count"],
            "avg_rating": metrics["avg_rating"],
            "order_count": metrics["order_count"],
            "sold_quantity": metrics["sold_quantity"],
            "homepage_score": metrics["top_score"],
            "featured_score": metrics["featured_score"],
            "cta_label": "Register to buy",
            "gate_action": "register_to_buy",
        }
    )
    return payload


def _build_homepage_records(rows: list[Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for product, farmer_name, farmer_location in rows:
        payload = _serialize_homepage_product(
            product,
            farmer_name=farmer_name,
            farmer_location=farmer_location,
        )
        records.append(
            {
                "product": product,
                "farmer_name": farmer_name or "Farmer",
                "farmer_location": farmer_location or "",
                "payload": payload,
                "metrics": _product_metrics(product),
            }
        )
    return records


def _build_homepage_categories(records: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    categories: dict[str, dict[str, Any]] = {}

    for record in records:
        payload = record["payload"]
        category = _canonical_category(payload.get("category"))
        bucket = categories.setdefault(
            category,
            {
                "category": category,
                "count": 0,
                "image_url": payload.get("image_url") or default_image_url(),
                "preview_names": [],
            },
        )
        bucket["count"] += 1
        if not bucket.get("image_url") and payload.get("image_url"):
            bucket["image_url"] = payload.get("image_url")

        name = str(payload.get("name") or payload.get("product_name") or "Product").strip()
        if name and name not in bucket["preview_names"] and len(bucket["preview_names"]) < 3:
            bucket["preview_names"].append(name)

    out = []
    for item in categories.values():
        out.append(
            {
                "category": item["category"],
                "count": item["count"],
                "product_count": item["count"],
                "image_url": item["image_url"] or default_image_url(),
                "preview_names": item["preview_names"],
                "tagline": _category_tagline(item["category"]),
            }
        )

    out.sort(key=lambda row: (-int(row.get("count", 0)), str(row.get("category", ""))))
    return out[:limit]


def _build_featured_products(records: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    ordered = sorted(
        records,
        key=lambda row: (
            -_safe_float(row["metrics"].get("featured_score"), 0.0),
            -_safe_float(row["metrics"].get("avg_rating"), 0.0),
            str(row["payload"].get("created_at") or ""),
        ),
    )
    return [row["payload"] for row in ordered[:limit]]


def _build_top_products(records: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    ordered = sorted(
        records,
        key=lambda row: (
            -_safe_float(row["metrics"].get("top_score"), 0.0),
            -_safe_float(row["metrics"].get("order_count"), 0.0),
            -_safe_float(row["metrics"].get("avg_rating"), 0.0),
            str(row["payload"].get("created_at") or ""),
        ),
    )
    return [row["payload"] for row in ordered[:limit]]


def _build_top_farmers(records: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    farmers: dict[str, dict[str, Any]] = {}

    for record in records:
        payload = record["payload"]
        metrics = record["metrics"]
        farmer_id = str(payload.get("farmer_id") or payload.get("user_id") or "").strip()
        if not farmer_id:
            continue

        bucket = farmers.setdefault(
            farmer_id,
            {
                "farmer_id": farmer_id,
                "farmer_name": record["farmer_name"] or "Farmer",
                "location": record["farmer_location"] or payload.get("location") or "",
                "product_count": 0,
                "category_names": set(),
                "product_names": [],
                "total_stock": 0.0,
                "total_orders": 0,
                "sold_quantity": 0.0,
                "rating_weighted_sum": 0.0,
                "rating_count": 0,
                "score": 0.0,
                "hero_image_url": "",
                "hero_image_candidates": [],
            },
        )

        bucket["product_count"] += 1
        category = _canonical_category(payload.get("category"))
        bucket["category_names"].add(category)
        bucket["total_stock"] += _safe_float(payload.get("stock") or payload.get("quantity"), 0.0)
        bucket["total_orders"] += int(_safe_float(metrics.get("order_count"), 0.0))
        bucket["sold_quantity"] += _safe_float(metrics.get("sold_quantity"), 0.0)
        bucket["rating_weighted_sum"] += _safe_float(metrics.get("avg_rating"), 0.0) * int(
            metrics.get("rating_count") or 0
        )
        bucket["rating_count"] += int(metrics.get("rating_count") or 0)
        bucket["score"] += _safe_float(metrics.get("top_score"), 0.0)

        pname = str(payload.get("name") or payload.get("product_name") or "Product").strip()
        if pname and pname not in bucket["product_names"] and len(bucket["product_names"]) < 3:
            bucket["product_names"].append(pname)

        # IMPORTANT:
        # Keep several real product-image candidates per farmer so the frontend
        # can retry the next image if one specific product photo is stale/missing.
        _append_unique_image_candidate(bucket["hero_image_candidates"], payload.get("image_url"))

        if not bucket.get("hero_image_url") and bucket["hero_image_candidates"]:
            bucket["hero_image_url"] = bucket["hero_image_candidates"][0]

    out: list[dict[str, Any]] = []
    for farmer in farmers.values():
        rating_count = int(farmer["rating_count"] or 0)
        avg_rating = round(farmer["rating_weighted_sum"] / rating_count, 2) if rating_count else 0.0
        hero_candidates = list(farmer.get("hero_image_candidates") or [])[:6]
        hero_image_url = hero_candidates[0] if hero_candidates else default_image_url()

        out.append(
            {
                "farmer_id": farmer["farmer_id"],
                "farmer_name": farmer["farmer_name"],
                "location": farmer["location"],
                "product_count": farmer["product_count"],
                "category_count": len(farmer["category_names"]),
                "featured_categories": sorted(farmer["category_names"])[:3],
                "top_product_names": farmer["product_names"],
                "total_stock": round(farmer["total_stock"], 2),
                "total_orders": farmer["total_orders"],
                "sold_quantity": round(farmer["sold_quantity"], 2),
                "rating_count": rating_count,
                "avg_rating": avg_rating,
                "image_url": hero_image_url,
                "avatar_url": hero_image_url,
                "hero_image_url": hero_image_url,
                "hero_image_candidates": hero_candidates,
                "score": round(farmer["score"], 3),
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


def _empty_homepage_payload() -> dict[str, Any]:
    return {
        "success": True,
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
        "sections": {
            "categories": [],
            "featured_products": [],
            "top_products": [],
            "top_farmers": [],
        },
    }


def _best_effort_notify_farmer(*, product: Product, status: str, reason: str | None = None) -> None:
    """
    Best-effort: DB notification + SMS + email (if available).
    Non-blocking by design.

    IMPORTANT NOTIFICATION SCHEMA NOTE:
      The current notifications schema uses:
        - notification_type
      not:
        - type

      So we avoid direct `n.type = ...` assignment and instead populate
      `notification_type` via _maybe_set(...). This removes the static typing
      error and matches the actual DB/model naming.
    """
    try:
        owner = _owner_id(product)
        if not owner:
            return

        product_name = getattr(product, "product_name", "Product")
        message = (
            f"Your product '{product_name}' was approved and is now visible in the marketplace."
            if status in {"approved", "available"}
            else f"Your product '{product_name}' was rejected. Reason: {reason or 'No reason provided.'}"
        )

        if Notification is not None:
            try:
                n = Notification()  # type: ignore[call-arg]

                _maybe_set(n, "user_id", owner)
                _maybe_set(n, "title", "Product Review Update")
                _maybe_set(n, "message", message)
                _maybe_set(n, "notification_type", "product_review")
                _maybe_set(n, "type", "product_review")
                _maybe_set(n, "created_at", datetime.utcnow())
                _maybe_set(n, "updated_at", datetime.utcnow())
                _maybe_set(n, "is_read", False)

                db.session.add(n)  # type: ignore[attr-defined]
                db.session.flush()  # type: ignore[attr-defined]
            except Exception:
                pass

        try:
            u = db.session.get(User, owner)  # type: ignore[attr-defined]
        except Exception:
            u = None

        if send_sms is not None and u is not None:
            phone = getattr(u, "phone", None) or getattr(u, "phone_number", None)
            if phone:
                try:
                    send_sms(str(phone), message)  # type: ignore[misc]
                except Exception:
                    pass

        if send_email is not None and u is not None:
            email = getattr(u, "email", None)
            if email:
                try:
                    send_email(str(email), "AgroConnect Product Review Update", message)  # type: ignore[misc]
                except Exception:
                    pass
    except Exception:
        return


def _apply_search_filters(stmt: Any, q: str, category: str, location: str) -> Any:
    owner_fk = _owner_fk_column()

    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                Product.product_name.ilike(like),
                Product.description.ilike(like),
                Product.category.ilike(like),
                User.full_name.ilike(like),
                User.location.ilike(like),
            )
        )

    if category:
        stmt = stmt.where(Product.category == _canonical_category(category))

    if location:
        stmt = stmt.where(User.location == location)

    return stmt


def _apply_sort(stmt: Any, sort: str) -> Any:
    """
    Allowed sort:
      - newest (default)
      - price_asc
      - price_desc
      - name_asc
      - name_desc
      - stock_desc
    """
    sort = (sort or "newest").strip().lower()

    if sort == "price_asc":
        return stmt.order_by(Product.price.asc())
    if sort == "price_desc":
        return stmt.order_by(Product.price.desc())
    if sort == "name_asc":
        return stmt.order_by(Product.product_name.asc())
    if sort == "name_desc":
        return stmt.order_by(Product.product_name.desc())
    if sort == "stock_desc":
        qty_col = getattr(Product, "quantity", None)
        if qty_col is not None:
            return stmt.order_by(qty_col.desc())
        return stmt.order_by(_created_at_column().desc())

    return stmt.order_by(_created_at_column().desc())


# --------------------------------------------------------------------
# Public + dashboard route (same endpoint, safe behavior)
# --------------------------------------------------------------------
@products_bp.get("/", strict_slashes=False)
def list_products() -> Any:
    """
    Public marketplace:
      - shows only PUBLIC statuses

    Dashboard mode:
      - enabled only with valid JWT (optional auth)
      - user is FARMER/ADMIN
      - farmerId matches when farmer role
    """
    q = (request.args.get("q") or "").strip()
    category = (request.args.get("category") or "").strip()
    location = (request.args.get("location") or "").strip()

    limit = max(1, min(_to_int(request.args.get("limit", 200), 200), 500))
    offset = max(0, _to_int(request.args.get("offset", 0), 0))
    sort = (request.args.get("sort") or "newest").strip()

    user, auth_err = _maybe_auth_user()
    if auth_err is not None:
        return auth_err

    farmer_id = _to_uuid(
        request.args.get("farmerId")
        or request.args.get("farmer_id")
        or request.args.get("ownerId")
        or request.args.get("owner_id")
    )

    owner_fk = _owner_fk_column()

    if isinstance(user, User) and user.role in (ROLE_FARMER, ROLE_ADMIN):
        target_id: Optional[UUID | str] = None

        if farmer_id:
            target_id = farmer_id
        elif user.role == ROLE_FARMER:
            target_id = _to_uuid(user.id) or user.id  # type: ignore[assignment]

        if target_id:
            if user.role == ROLE_FARMER and str(target_id) != str(user.id):
                return _json_error("Forbidden", 403)

            stmt = (
                select(Product, User.full_name, User.location)
                .join(User, User.id == owner_fk, isouter=True)
                .where(owner_fk == target_id)
            )

            stmt = _apply_search_filters(stmt, q, category, location)

            status = (request.args.get("status") or "").strip().lower()
            if status and status != "all" and status in _ALLOWED_STATUSES:
                stmt = stmt.where(Product.status == status)

            stmt = _apply_sort(stmt, sort).offset(offset).limit(limit)

            rows = db.session.execute(stmt).all()  # type: ignore[attr-defined]
            out = [
                _serialize_product(p, farmer_name=fn, farmer_location=fl, include_moderation=True)
                for (p, fn, fl) in rows
            ]
            return jsonify({"products": out, "count": len(out), "offset": offset, "limit": limit})

    stmt = (
        select(Product, User.full_name, User.location)
        .join(User, User.id == owner_fk, isouter=True)
        .where(Product.status.in_(sorted(_PUBLIC_STATUSES)))
    )

    stmt = _apply_search_filters(stmt, q, category, location)
    stmt = _apply_sort(stmt, sort).offset(offset).limit(limit)

    rows = db.session.execute(stmt).all()  # type: ignore[attr-defined]
    out = [
        _serialize_product(p, farmer_name=fn, farmer_location=fl, include_moderation=False)
        for (p, fn, fl) in rows
    ]
    return jsonify({"products": out, "count": len(out), "offset": offset, "limit": limit})


@products_bp.get("/new", strict_slashes=False)
def list_new_products() -> Any:
    """
    Public "new products" feed.

    RULE:
      Only return products created within the last N days.
      Default window = 7 days.

    QUERY PARAMS:
      - limit: max number of rows to return (default 24, hard cap 50)
      - days: recency window in days (default 7, hard cap 30)
    """
    limit = max(1, min(_to_int(request.args.get("limit", 24), 24), 50))
    days = max(
        1,
        min(
            _to_int(request.args.get("days", _DEFAULT_NEW_PRODUCT_DAYS), _DEFAULT_NEW_PRODUCT_DAYS),
            _MAX_NEW_PRODUCT_DAYS,
        ),
    )

    owner_fk = _owner_fk_column()
    created_col = getattr(Product, "created_at", None)
    cutoff = datetime.utcnow() - timedelta(days=days)

    stmt = (
        select(Product, User.full_name, User.location)
        .join(User, User.id == owner_fk, isouter=True)
        .where(Product.status.in_(sorted(_PUBLIC_STATUSES)))
    )

    if created_col is not None:
        stmt = stmt.where(created_col >= cutoff).order_by(created_col.desc())
    else:
        stmt = stmt.order_by(_created_at_column().desc())

    stmt = stmt.limit(limit)

    rows = db.session.execute(stmt).all()  # type: ignore[attr-defined]
    out = [
        _serialize_product(p, farmer_name=fn, farmer_location=fl, include_moderation=False)
        for (p, fn, fl) in rows
    ]
    return _wrap_products(out)


@products_bp.get("/top-selling", strict_slashes=False)
def list_top_selling() -> Any:
    return list_new_products()


@products_bp.get("/suggest-category", strict_slashes=False)
def suggest_category() -> Any:
    q = (request.args.get("q") or "").strip()
    return jsonify({"category": _canonical_category(q)})


@products_bp.get("/homepage", strict_slashes=False)
def get_products_homepage() -> Any:
    """
    Public marketplace homepage payload.

    DESIGN NOTES:
      - Read-only endpoint: safe for anonymous visitors
      - Reuses existing product serialization to avoid breaking other flows
      - Does not interfere with USSD routes/services because it only reads public
        marketplace data from the core products table
      - Provides frontend-friendly sections for:
          * categories
          * featured product slider
          * top products
          * top farmers
    """
    category_limit = max(1, min(_to_int(request.args.get("category_limit", 8), 8), 12))
    featured_limit = max(1, min(_to_int(request.args.get("featured_limit", 6), 6), 12))
    top_products_limit = max(1, min(_to_int(request.args.get("top_products_limit", 8), 8), 12))
    top_farmers_limit = max(1, min(_to_int(request.args.get("top_farmers_limit", 6), 6), 10))
    scan_limit = max(24, min(_to_int(request.args.get("scan_limit", 240), 240), 600))

    owner_fk = _owner_fk_column()
    stmt = (
        select(Product, User.full_name, User.location)
        .join(User, User.id == owner_fk, isouter=True)
        .where(Product.status.in_(sorted(_PUBLIC_STATUSES)))
        .options(
            selectinload(Product.ratings),
            selectinload(Product.order_items),
        )
        .order_by(_created_at_column().desc())
        .limit(scan_limit)
    )

    rows = db.session.execute(stmt).unique().all()  # type: ignore[attr-defined]
    if not rows:
        return jsonify(_empty_homepage_payload())

    records = _build_homepage_records(rows)
    categories = _build_homepage_categories(records, category_limit)
    featured_products = _build_featured_products(records, featured_limit)
    top_products = _build_top_products(records, top_products_limit)
    top_farmers = _build_top_farmers(records, top_farmers_limit)

    unique_farmers = {
        str(r["payload"].get("farmer_id") or r["payload"].get("user_id") or "").strip()
        for r in records
        if str(r["payload"].get("farmer_id") or r["payload"].get("user_id") or "").strip()
    }
    unique_categories = {_canonical_category(r["payload"].get("category")) for r in records}

    payload = {
        "success": True,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_public_products": len(records),
            "total_categories": len(unique_categories),
            "total_public_farmers": len(unique_farmers),
            "featured_count": len(featured_products),
        },
        "categories": categories,
        "featured_products": featured_products,
        "top_products": top_products,
        "top_farmers": top_farmers,
        "sections": {
            "categories": categories,
            "featured_products": featured_products,
            "top_products": top_products,
            "top_farmers": top_farmers,
        },
        "register_gate": {
            "buy_label": "Register to buy",
            "sell_label": "Register to sell",
            "login_label": "Login",
            "message": "Visitors can explore the marketplace, but buying and selling require registration.",
        },
    }
    return jsonify(payload)


@products_bp.get("/<string:product_id>", strict_slashes=False)
def get_product(product_id: str) -> Any:
    pid = _to_uuid(product_id)
    if not pid:
        return _json_error("Invalid product id", 400)

    owner_fk = _owner_fk_column()
    pk_col = _pk_column()

    stmt = (
        select(Product, User.full_name, User.location)
        .join(User, User.id == owner_fk, isouter=True)
        .where(pk_col == pid)
        .where(Product.status.in_(sorted(_PUBLIC_STATUSES)))
    )

    row = db.session.execute(stmt).first()  # type: ignore[attr-defined]
    if not row:
        return _json_error("Product not found", 404)

    product, fn, fl = row
    return jsonify(
        {
            "product": _serialize_product(
                product,
                farmer_name=fn,
                farmer_location=fl,
                include_moderation=False,
            )
        }
    )


# --------------------------------------------------------------------
# Farmer/Admin protected: MY PRODUCTS
# --------------------------------------------------------------------
@products_bp.get("/mine", strict_slashes=False)
@require_access_token
def list_my_products() -> Any:
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    limit = max(1, min(_to_int(request.args.get("limit", 500), 500), 500))
    owner_fk = _owner_fk_column()

    stmt = (
        select(Product)
        .where(owner_fk == user.id)
        .order_by(_created_at_column().desc())
        .limit(limit)
    )

    rows = db.session.execute(stmt).scalars().all()  # type: ignore[attr-defined]
    out = [
        _serialize_product(
            p,
            farmer_name=user.full_name,
            farmer_location=user.location,
            include_moderation=True,
        )
        for p in rows
    ]
    return _wrap_products(out)


# --------------------------------------------------------------------
# CREATE (Farmer => pending)
# --------------------------------------------------------------------
@products_bp.post("/", strict_slashes=False)
@require_access_token
def create_product() -> Any:
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    if user.role not in (ROLE_FARMER, ROLE_ADMIN):
        return _json_error("Permission denied", 403)

    data = _payload()
    name = (data.get("product_name") or data.get("name") or "").strip()
    if not name:
        return _json_error("product_name is required", 400)

    description = str(data.get("description") or "").strip()
    category = _canonical_category(data.get("category") or "")

    explicit_image_url = str(data.get("image_url") or data.get("imageUrl") or "").strip()
    if explicit_image_url:
        image_url = _normalize_image_url_or_filename(explicit_image_url)
    else:
        try:
            uploaded = save_image(request.files.get("image"), folder="products")
            image_url = _normalize_image_url_or_filename(uploaded or default_image_url())
        except Exception:
            image_url = default_image_url()

    qty = _to_qty_decimal(data.get("quantity"), Decimal("0.000"))
    if qty < 0:
        return _json_error("quantity must be >= 0", 400)

    product = Product()
    product.product_name = name
    product.description = description or None
    product.category = category
    product.price = _to_money_decimal(data.get("price"), Decimal("0.00"))
    product.quantity = qty
    product.image_url = image_url

    _set_owner(product, user.id)

    err = _apply_c1_unit_fields(product, data)
    if err:
        return err

    if user.role == ROLE_ADMIN:
        proposed = str(data.get("status") or "available").strip().lower()
        product.status = proposed if proposed in _ALLOWED_STATUSES else "available"

        if product.status in {"available", "approved"} and hasattr(product, "build_moderation_snapshot"):
            product.moderation_snapshot = product.build_moderation_snapshot()  # type: ignore[assignment]
            product.moderation_changes = None  # type: ignore[assignment]
    else:
        product.status = "pending"

    _maybe_set(product, "last_edited_by", user.id)
    _maybe_set(product, "last_edited_at", datetime.utcnow())

    _maybe_set(product, "rejection_reason", None)
    _maybe_set(product, "reviewed_by", None)
    _maybe_set(product, "reviewed_at", None)

    db.session.add(product)  # type: ignore[attr-defined]
    db.session.commit()  # type: ignore[attr-defined]

    resp = jsonify(
        {
            "product": _serialize_product(
                product,
                farmer_name=user.full_name,
                farmer_location=user.location,
                include_moderation=True,
            )
        }
    )
    resp.status_code = 201
    return resp


# --------------------------------------------------------------------
# UPDATE helpers
# --------------------------------------------------------------------
def _clear_review_fields(product: Product) -> None:
    _maybe_set(product, "rejection_reason", None)
    _maybe_set(product, "reviewed_by", None)
    _maybe_set(product, "reviewed_at", None)


def _update_product_common(product: Product, user: User, data: dict[str, Any]) -> Any:
    if user.role != ROLE_ADMIN and str(_owner_id(product)) != str(user.id):
        return _json_error("You do not own this product", 403)

    if user.role == ROLE_ADMIN:
        setattr(product, "_moderation_actor", "admin")

    major_change = False

    if "product_name" in data or "name" in data:
        product.product_name = (data.get("product_name") or data.get("name") or "").strip()
        major_change = True

    if "description" in data:
        product.description = str(data.get("description") or "").strip() or None
        major_change = True

    if "category" in data:
        product.category = _canonical_category(data.get("category"))
        major_change = True

    if "price" in data:
        product.price = _to_money_decimal(
            data.get("price"),
            Decimal(str(getattr(product, "price", "0.00"))),
        )
        major_change = True

    if "quantity" in data or "stock" in data or "qty" in data:
        raw = data.get("quantity", data.get("stock", data.get("qty")))
        qty = _to_qty_decimal(raw, Decimal(str(getattr(product, "quantity", "0.000"))))
        if qty < 0:
            return _json_error("quantity must be >= 0", 400)
        product.quantity = qty

    if "unit" in data or "pack_size" in data or "pack_unit" in data:
        err = _apply_c1_unit_fields(product, data)
        if err:
            return err
        major_change = True

    if "image_url" in data or "imageUrl" in data:
        raw_url = str(data.get("image_url") or data.get("imageUrl") or "").strip()
        if raw_url:
            product.image_url = _normalize_image_url_or_filename(raw_url)  # type: ignore[assignment]
            major_change = True

    try:
        new_url = save_image(request.files.get("image"), folder="products")
        if new_url:
            product.image_url = _normalize_image_url_or_filename(new_url)
            major_change = True
    except Exception:
        pass

    _maybe_set(product, "last_edited_by", user.id)
    _maybe_set(product, "last_edited_at", datetime.utcnow())

    if "status" in data:
        new_status = str(data.get("status") or "").strip().lower()

        if user.role == ROLE_ADMIN:
            if new_status not in _ALLOWED_STATUSES:
                return _json_error(f"Invalid status '{new_status}'", 400)

            product.status = new_status
            _maybe_set(product, "reviewed_by", user.id)
            _maybe_set(product, "reviewed_at", datetime.utcnow())
            _maybe_set(product, "status_updated_at", datetime.utcnow())

            if new_status in {"approved", "available"}:
                _maybe_set(product, "rejection_reason", None)
                if hasattr(product, "build_moderation_snapshot"):
                    _maybe_set(product, "moderation_snapshot", product.build_moderation_snapshot())
                _maybe_set(product, "moderation_changes", None)
                _best_effort_notify_farmer(product=product, status=new_status, reason=None)

            if new_status == "rejected":
                reason = str(data.get("rejection_reason") or data.get("reason") or "").strip()
                if not reason:
                    return _json_error("rejection_reason is required when rejecting", 400)
                _maybe_set(product, "rejection_reason", reason)
                _best_effort_notify_farmer(product=product, status="rejected", reason=reason)

        else:
            if new_status == "unavailable":
                product.status = "unavailable"
            elif new_status == "pending":
                product.status = "pending"
                _clear_review_fields(product)
            else:
                return _json_error("Only admin can set this status", 403)

    current_status = str(getattr(product, "status", "") or "").lower()
    if user.role != ROLE_ADMIN:
        if current_status == "rejected" or major_change:
            product.status = "pending"
            _clear_review_fields(product)

    db.session.commit()  # type: ignore[attr-defined]
    return jsonify(
        {
            "product": _serialize_product(
                product,
                farmer_name=user.full_name,
                farmer_location=user.location,
                include_moderation=True,
            )
        }
    )


@products_bp.put("/<string:product_id>", strict_slashes=False)
@require_access_token
def update_product(product_id: str) -> Any:
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    pid = _to_uuid(product_id)
    if not pid:
        return _json_error("Invalid product id", 400)

    product = db.session.get(Product, pid)  # type: ignore[attr-defined]
    if not product:
        return _json_error("Product not found", 404)

    return _update_product_common(product, user, _payload())


@products_bp.route("/<string:product_id>", methods=["PATCH"], strict_slashes=False)
@require_access_token
def patch_product(product_id: str) -> Any:
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    pid = _to_uuid(product_id)
    if not pid:
        return _json_error("Invalid product id", 400)

    product = db.session.get(Product, pid)  # type: ignore[attr-defined]
    if not product:
        return _json_error("Product not found", 404)

    return _update_product_common(product, user, _payload())


@products_bp.delete("/<string:product_id>", strict_slashes=False)
@require_access_token
def delete_product(product_id: str) -> Any:
    user = getattr(request, "current_user", None)
    if not isinstance(user, User):
        return _json_error("Unauthorized", 401)

    pid = _to_uuid(product_id)
    if not pid:
        return _json_error("Invalid product id", 400)

    product = db.session.get(Product, pid)  # type: ignore[attr-defined]
    if not product:
        return _json_error("Product not found", 404)

    if user.role != ROLE_ADMIN and str(_owner_id(product)) != str(user.id):
        return _json_error("You do not own this product", 403)

    db.session.delete(product)  # type: ignore[attr-defined]
    db.session.commit()  # type: ignore[attr-defined]
    return jsonify({"success": True, "message": "Product deleted"})