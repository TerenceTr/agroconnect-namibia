# ============================================================================
# backend/routes/ratings.py — Ratings API (Phase 3 admin governance)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Verified review submission + farmer workflow + admin governance.
#
# PHASE 3:
#   ✅ Review flags
#   ✅ Admin moderation queue
#   ✅ Policy actions
#   ✅ Dedicated review-governance audit log
#   ✅ Public product pages automatically hide moderated reviews
#
# FIXES IN THIS VERSION:
#   ✅ Avoids typed-constructor errors for AdminAuditLog(...)
#   ✅ Avoids `.where(... else True)` type-checking errors
#   ✅ Preserves Phase 1 + Phase 2 review and farmer-response workflows
#   ✅ Keeps schema-compatible attribute assignment across model variants
# ============================================================================

from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Any, Optional, cast
from uuid import UUID

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from sqlalchemy import func, or_, select

from backend.database.db import db
from backend.models.order import Order
from backend.models.order_item import OrderItem
from backend.models.product import Product
from backend.models.user import User
from backend.utils.require_auth import require_access_token

try:
    from backend.models.rating import Rating
except Exception:  # pragma: no cover
    Rating = None  # type: ignore[assignment]

try:
    from backend.models.rating_response import RatingResponse
except Exception:  # pragma: no cover
    RatingResponse = None  # type: ignore[assignment]

try:
    from backend.models.rating_flag import RatingFlag
except Exception:  # pragma: no cover
    RatingFlag = None  # type: ignore[assignment]

try:
    from backend.models.review_policy_action import ReviewPolicyAction
except Exception:  # pragma: no cover
    ReviewPolicyAction = None  # type: ignore[assignment]

try:
    from backend.models.admin_audit_event import AdminAuditLog
except Exception:  # pragma: no cover
    AdminAuditLog = None  # type: ignore[assignment]

ratings_bp = Blueprint("ratings", __name__)

RESPONSE_SLA_HOURS = 48

PUBLIC_VISIBLE_MODERATION_STATUSES = {"visible", "published", "approved"}

MODERATION_STATUSES = (
    "visible",
    "flagged",
    "under_review",
    "hidden",
    "removed",
    "published",
)

FLAG_REASONS = (
    "abusive_language",
    "spam",
    "fake_review",
    "harassment",
    "defamation",
    "privacy_violation",
    "wrong_product",
    "other",
)

POLICY_ACTIONS = (
    "publish_review",
    "hide_review",
    "remove_review",
    "restore_review",
    "dismiss_flags",
    "mark_under_review",
    "warn_farmer",
    "warn_customer",
)

ISSUE_TAGS: tuple[str, ...] = (
    "freshness",
    "quality",
    "packaging",
    "delivery_delay",
    "wrong_item",
    "quantity",
    "communication",
    "value",
    "damaged",
    "other",
)

RESOLUTION_STATUSES: tuple[str, ...] = (
    "open",
    "acknowledged",
    "in_progress",
    "resolved",
)

RESPONSE_STATUS_FILTERS: tuple[str, ...] = (
    "all",
    "needs_response",
    "responded",
    "sla_breached",
    "responded_late",
    "responded_on_time",
)


# ----------------------------------------------------------------------------
# Small safe helpers
# ----------------------------------------------------------------------------
def _utc_now() -> datetime:
    return datetime.utcnow()


def _uuid(v: Any) -> Optional[UUID]:
    try:
        s = str(v or "").strip()
        return UUID(s) if s else None
    except Exception:
        return None


def _int(v: Any, default: int) -> int:
    try:
        s = str(v or "").strip()
        return int(s) if s else default
    except Exception:
        return default


def _float(v: Any, default: float) -> float:
    try:
        if v is None:
            return default
        return float(v)
    except Exception:
        return default


def _bool_arg(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _dt_iso(v: Any) -> Optional[str]:
    if isinstance(v, datetime):
        return v.isoformat()
    if isinstance(v, date):
        return datetime(v.year, v.month, v.day).isoformat()
    return None


def _err(msg: str, status: int):
    resp = jsonify({"success": False, "message": msg})
    resp.status_code = status
    return resp


def _first_value(obj: Any, *names: str) -> Any:
    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return None


def _set_first_attr(obj: Any, names: tuple[str, ...], value: Any) -> bool:
    for name in names:
        if hasattr(obj, name):
            try:
                setattr(obj, name, value)
                return True
            except Exception:
                return False
    return False


def _normalized_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_text(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def _required_col(value: Optional[Any]) -> Any:
    return cast(Any, value)


def _json_meta(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


# ----------------------------------------------------------------------------
# Role helpers
# ----------------------------------------------------------------------------
def _current_user_id(current_user: Any) -> Optional[UUID]:
    return _uuid(_first_value(current_user, "id", "user_id"))


def _current_user_is_farmer(current_user: Any) -> bool:
    if current_user is None:
        return False
    if getattr(current_user, "is_farmer", False):
        return True

    role_name = _safe_text(getattr(current_user, "role_name", None)).lower()
    if role_name:
        return role_name == "farmer"

    try:
        return int(getattr(current_user, "role", 0) or 0) == 2
    except Exception:
        return False


def _current_user_is_admin(current_user: Any) -> bool:
    if current_user is None:
        return False
    if getattr(current_user, "is_admin", False):
        return True

    role_name = _safe_text(getattr(current_user, "role_name", None)).lower()
    if role_name:
        return role_name == "admin"

    try:
        return int(getattr(current_user, "role", 0) or 0) == 1
    except Exception:
        return False


# ----------------------------------------------------------------------------
# Reviewability helpers
# ----------------------------------------------------------------------------
def _is_order_complete(order: Order | None) -> bool:
    if order is None:
        return False

    order_status = _normalized_status(
        getattr(order, "status", None) or getattr(order, "order_status", None)
    )
    delivery_status = _normalized_status(getattr(order, "delivery_status", None))
    return order_status in {"completed", "complete", "delivered"} or delivery_status == "delivered"


def _is_item_delivered(item: OrderItem | None) -> bool:
    if item is None:
        return False

    item_delivery = _normalized_status(
        getattr(item, "delivery_status", None) or getattr(item, "item_delivery_status", None)
    )
    item_fulfillment = _normalized_status(getattr(item, "fulfillment_status", None))
    return item_delivery == "delivered" or item_fulfillment in {"completed", "complete", "delivered"}


def _is_reviewable_purchase(order: Order | None, item: OrderItem | None) -> bool:
    return _is_item_delivered(item) or _is_order_complete(order)


# ----------------------------------------------------------------------------
# Schema compatibility helpers
# ----------------------------------------------------------------------------
def _product_pk() -> Optional[Any]:
    for name in ("product_id", "id", "productId"):
        if hasattr(Product, name):
            return getattr(Product, name)
    return None


def _product_owner() -> Optional[Any]:
    for name in ("user_id", "farmer_id", "owner_id", "created_by_id", "seller_id"):
        if hasattr(Product, name):
            return getattr(Product, name)
    return None


def _user_pk() -> Optional[Any]:
    for name in ("id", "user_id"):
        if hasattr(User, name):
            return getattr(User, name)
    return None


def _best_user_name(u: Any) -> str:
    for name in ("full_name", "name", "username", "first_name", "firstName", "email"):
        if hasattr(u, name):
            value = getattr(u, name)
            if value:
                return str(value).strip()
    return "Customer"


def _best_user_location(u: Any) -> Optional[str]:
    for name in ("location", "address", "region", "city", "town", "constituency"):
        if hasattr(u, name):
            value = getattr(u, name)
            if value:
                s = str(value).strip()
                return s or None
    return None


def _rating_cols():
    if Rating is None:
        return (None, None, None, None, None, None)

    score = getattr(Rating, "rating_score", None) or getattr(Rating, "score", None)
    created = getattr(Rating, "created_at", None) or getattr(Rating, "createdAt", None)
    pid = getattr(Rating, "product_id", None) or getattr(Rating, "productId", None)
    rid = getattr(Rating, "id", None) or getattr(Rating, "rating_id", None)
    comments = getattr(Rating, "comments", None) or getattr(Rating, "comment", None)
    uid = getattr(Rating, "user_id", None) or getattr(Rating, "userId", None)
    return (score, created, pid, rid, comments, uid)


def _rating_order_col() -> Optional[Any]:
    if Rating is None:
        return None
    return getattr(Rating, "order_id", None) or getattr(Rating, "orderId", None)


def _rating_order_item_col() -> Optional[Any]:
    if Rating is None:
        return None
    return getattr(Rating, "order_item_id", None) or getattr(Rating, "orderItemId", None)


def _rating_verified_col() -> Optional[Any]:
    if Rating is None:
        return None
    return getattr(Rating, "verified_purchase", None) or getattr(Rating, "verifiedPurchase", None)


def _rating_issue_tag_col() -> Optional[Any]:
    if Rating is None:
        return None
    return getattr(Rating, "issue_tag", None)


def _rating_resolution_status_col() -> Optional[Any]:
    if Rating is None:
        return None
    return getattr(Rating, "resolution_status", None)


def _rating_first_response_col() -> Optional[Any]:
    if Rating is None:
        return None
    return getattr(Rating, "first_farmer_response_at", None)


def _rating_moderation_status_col() -> Optional[Any]:
    if Rating is None:
        return None
    return getattr(Rating, "moderation_status", None)


# ----------------------------------------------------------------------------
# Workflow helpers
# ----------------------------------------------------------------------------
def _normalize_issue_tag(value: Any) -> Optional[str]:
    s = _safe_text(value).lower().replace(" ", "_")
    if not s:
        return None
    return s if s in ISSUE_TAGS else "other"


def _normalize_resolution_status(value: Any) -> str:
    s = _safe_text(value, "open").lower()
    return s if s in RESOLUTION_STATUSES else "open"


def _normalize_flag_reason(value: Any) -> str:
    s = _safe_text(value, "other").lower().replace(" ", "_")
    return s if s in FLAG_REASONS else "other"


def _normalize_policy_action(value: Any) -> str:
    s = _safe_text(value).lower()
    return s if s in POLICY_ACTIONS else "mark_under_review"


def _normalize_moderation_status(value: Any) -> str:
    s = _safe_text(value, "visible").lower()
    return s if s in MODERATION_STATUSES else "visible"


def _response_sla_due_at(created_at: Any) -> Optional[datetime]:
    if not isinstance(created_at, datetime):
        return None
    return created_at + timedelta(hours=RESPONSE_SLA_HOURS)


def _response_sla_status(created_at: Any, first_response_at: Any) -> str:
    if not isinstance(created_at, datetime):
        return "unknown"

    due_at = _response_sla_due_at(created_at)
    if due_at is None:
        return "unknown"

    if isinstance(first_response_at, datetime):
        return "responded_on_time" if first_response_at <= due_at else "responded_late"

    return "sla_breached" if _utc_now() > due_at else "needs_response"


def _response_sla_hours_remaining(created_at: Any, first_response_at: Any) -> Optional[float]:
    if not isinstance(created_at, datetime) or isinstance(first_response_at, datetime):
        return None

    due_at = _response_sla_due_at(created_at)
    if due_at is None:
        return None

    return round((due_at - _utc_now()).total_seconds() / 3600.0, 2)


def _response_status_matches(filter_value: str, status: str) -> bool:
    if filter_value in {"", "all"}:
        return True
    return filter_value == status


def _farmer_owns_rating(rating_obj: Any, farmer_uid: UUID) -> bool:
    if rating_obj is None:
        return False

    product = getattr(rating_obj, "product", None)
    if product is not None:
        owner = _uuid(
            getattr(product, "user_id", None)
            or getattr(product, "farmer_id", None)
            or getattr(product, "owner_id", None)
            or getattr(product, "created_by_id", None)
            or getattr(product, "seller_id", None)
        )
        if owner is not None:
            return owner == farmer_uid

    pid = _uuid(getattr(rating_obj, "product_id", None))
    if pid is None:
        return False

    product_owner_col = _product_owner()
    product_pk = _product_pk()
    if product_owner_col is None or product_pk is None:
        return False

    owner_val = db.session.scalar(
        select(product_owner_col).select_from(Product).where(product_pk == pid).limit(1)
    )
    return _uuid(owner_val) == farmer_uid


def _public_visibility_clause(moderation_status_col: Optional[Any]) -> Optional[Any]:
    """
    Build a SQLAlchemy expression for public review visibility.

    FIX:
    We return either a real SQLAlchemy clause or None.
    We do NOT return literal True, because `.where(True)` triggers static
    type-checker errors in this project setup.
    """
    if moderation_status_col is None:
        return None

    return or_(
        moderation_status_col.is_(None),
        moderation_status_col.in_(tuple(PUBLIC_VISIBLE_MODERATION_STATUSES)),
    )


# ----------------------------------------------------------------------------
# Serialization helpers
# ----------------------------------------------------------------------------
def _serialize_response(resp: Any) -> dict[str, Any]:
    if hasattr(resp, "to_dict") and callable(getattr(resp, "to_dict")):
        try:
            out = resp.to_dict()
            if isinstance(out, dict):
                return out
        except Exception:
            pass

    responder = getattr(resp, "responder", None)
    responder_name = _best_user_name(responder) if responder is not None else "Farmer"

    return {
        "response_id": str(getattr(resp, "response_id", None) or getattr(resp, "id", None) or "") or None,
        "id": str(getattr(resp, "response_id", None) or getattr(resp, "id", None) or "") or None,
        "rating_id": str(getattr(resp, "rating_id", None) or "") or None,
        "responder_user_id": str(getattr(resp, "responder_user_id", None) or "") or None,
        "responder_role": _safe_text(getattr(resp, "responder_role", None), "farmer") or "farmer",
        "responder_name": responder_name,
        "response_text": _safe_text(getattr(resp, "response_text", None)),
        "is_public": bool(getattr(resp, "is_public", True)),
        "created_at": _dt_iso(getattr(resp, "created_at", None)),
        "updated_at": _dt_iso(getattr(resp, "updated_at", None)),
    }


def _serialize_flag(flag: Any) -> dict[str, Any]:
    if hasattr(flag, "to_dict") and callable(getattr(flag, "to_dict")):
        try:
            out = flag.to_dict()
            if isinstance(out, dict):
                return out
        except Exception:
            pass

    return {
        "flag_id": str(getattr(flag, "flag_id", None) or getattr(flag, "id", None) or "") or None,
        "id": str(getattr(flag, "flag_id", None) or getattr(flag, "id", None) or "") or None,
        "rating_id": str(getattr(flag, "rating_id", None) or "") or None,
        "flagged_by_user_id": str(getattr(flag, "flagged_by_user_id", None) or "") or None,
        "reason_code": _safe_text(getattr(flag, "reason_code", None)),
        "notes": _safe_text(getattr(flag, "notes", None)),
        "status": _safe_text(getattr(flag, "status", None), "open"),
        "reviewed_by": str(getattr(flag, "reviewed_by", None) or "") or None,
        "reviewed_at": _dt_iso(getattr(flag, "reviewed_at", None)),
        "created_at": _dt_iso(getattr(flag, "created_at", None)),
    }


def _serialize_policy_action(action: Any) -> dict[str, Any]:
    if hasattr(action, "to_dict") and callable(getattr(action, "to_dict")):
        try:
            out = action.to_dict()
            if isinstance(out, dict):
                return out
        except Exception:
            pass

    metadata_value = getattr(action, "metadata_json", None)
    if metadata_value is None:
        metadata_value = getattr(action, "metadata", None)

    return {
        "action_id": str(getattr(action, "action_id", None) or getattr(action, "id", None) or "") or None,
        "id": str(getattr(action, "action_id", None) or getattr(action, "id", None) or "") or None,
        "rating_id": str(getattr(action, "rating_id", None) or "") or None,
        "admin_id": str(getattr(action, "admin_id", None) or "") or None,
        "action_type": _safe_text(getattr(action, "action_type", None) or getattr(action, "action", None)),
        "action_status": _safe_text(getattr(action, "action_status", None), "applied"),
        "rationale": _safe_text(getattr(action, "rationale", None)),
        "metadata": _json_meta(metadata_value),
        "created_at": _dt_iso(getattr(action, "created_at", None)),
    }


def _to_dict(r: Any) -> dict[str, Any]:
    if hasattr(r, "to_dict") and callable(getattr(r, "to_dict")):
        try:
            out = r.to_dict()
            if isinstance(out, dict):
                score_val = out.get("rating_score", out.get("score"))
                if score_val is not None and "score" not in out:
                    out["score"] = score_val
                if score_val is not None and "rating" not in out:
                    out["rating"] = score_val
                if "verified_purchase" not in out:
                    out["verified_purchase"] = bool(out.get("order_item_id"))
                return out
        except Exception:
            pass

    score = getattr(r, "rating_score", None)
    if score is None:
        score = getattr(r, "score", None)

    created_at = getattr(r, "created_at", None) or getattr(r, "createdAt", None)

    return {
        "id": str(getattr(r, "id", "")) or None,
        "rating_id": str(getattr(r, "rating_id", getattr(r, "id", ""))) or None,
        "product_id": str(getattr(r, "product_id", "")) or None,
        "user_id": str(getattr(r, "user_id", "")) or None,
        "order_id": str(getattr(r, "order_id", "")) or None,
        "order_item_id": str(getattr(r, "order_item_id", "")) or None,
        "rating_score": score,
        "score": score,
        "rating": score,
        "comments": getattr(r, "comments", None) or getattr(r, "comment", None),
        "comment": getattr(r, "comments", None) or getattr(r, "comment", None),
        "verified_purchase": bool(
            getattr(r, "verified_purchase", False) or getattr(r, "order_item_id", None)
        ),
        "issue_tag": getattr(r, "issue_tag", None),
        "resolution_status": getattr(r, "resolution_status", "open"),
        "first_farmer_response_at": _dt_iso(getattr(r, "first_farmer_response_at", None)),
        "last_farmer_response_at": _dt_iso(getattr(r, "last_farmer_response_at", None)),
        "moderation_status": getattr(r, "moderation_status", "visible"),
        "moderation_reason": getattr(r, "moderation_reason", None),
        "moderation_notes": getattr(r, "moderation_notes", None),
        "moderated_by": str(getattr(r, "moderated_by", None) or "") or None,
        "moderated_at": _dt_iso(getattr(r, "moderated_at", None)),
        "policy_action": getattr(r, "policy_action", None),
        "created_at": _dt_iso(created_at),
    }


def _load_public_responses_for_rating_ids(rating_ids: list[UUID]) -> dict[str, list[dict[str, Any]]]:
    if RatingResponse is None or not rating_ids:
        return {}

    out: dict[str, list[dict[str, Any]]] = {}
    try:
        rows = db.session.scalars(
            select(RatingResponse)
            .where(RatingResponse.rating_id.in_(rating_ids))
            .where(RatingResponse.is_public.is_(True))
            .order_by(RatingResponse.created_at.asc())
        ).all()
        for row in rows:
            key = str(getattr(row, "rating_id", None) or "")
            if not key:
                continue
            out.setdefault(key, []).append(_serialize_response(row))
    except Exception:
        return {}
    return out


def _load_flags_for_rating_ids(rating_ids: list[UUID]) -> dict[str, list[dict[str, Any]]]:
    if RatingFlag is None or not rating_ids:
        return {}

    out: dict[str, list[dict[str, Any]]] = {}
    try:
        rows = db.session.scalars(
            select(RatingFlag)
            .where(RatingFlag.rating_id.in_(rating_ids))
            .order_by(RatingFlag.created_at.desc())
        ).all()
        for row in rows:
            key = str(getattr(row, "rating_id", None) or "")
            if not key:
                continue
            out.setdefault(key, []).append(_serialize_flag(row))
    except Exception:
        return {}
    return out


def _load_policy_actions_for_rating_ids(rating_ids: list[UUID]) -> dict[str, list[dict[str, Any]]]:
    if ReviewPolicyAction is None or not rating_ids:
        return {}

    out: dict[str, list[dict[str, Any]]] = {}
    try:
        rows = db.session.scalars(
            select(ReviewPolicyAction)
            .where(ReviewPolicyAction.rating_id.in_(rating_ids))
            .order_by(ReviewPolicyAction.created_at.desc())
        ).all()
        for row in rows:
            key = str(getattr(row, "rating_id", None) or "")
            if not key:
                continue
            out.setdefault(key, []).append(_serialize_policy_action(row))
    except Exception:
        return {}
    return out


def _attach_public_responses(
    rating_dicts: list[dict[str, Any]],
    responses_by_rating: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []

    for item in rating_dicts:
        key = str(item.get("rating_id") or item.get("id") or "")
        public_responses = responses_by_rating.get(key, [])
        latest_public_response = public_responses[-1] if public_responses else None

        created_at = None
        try:
            raw_created = item.get("created_at")
            if raw_created:
                created_at = datetime.fromisoformat(str(raw_created))
        except Exception:
            created_at = None

        first_response_at = None
        try:
            raw_first = item.get("first_farmer_response_at")
            if raw_first:
                first_response_at = datetime.fromisoformat(str(raw_first))
        except Exception:
            first_response_at = None

        sla_status = _response_sla_status(created_at, first_response_at)
        due_at = _response_sla_due_at(created_at)
        hours_remaining = _response_sla_hours_remaining(created_at, first_response_at)

        next_item = {
            **item,
            "public_responses": public_responses,
            "public_response_count": len(public_responses),
            "latest_public_response": latest_public_response,
            "response_status": sla_status,
            "response_sla_status": sla_status,
            "response_sla_due_at": _dt_iso(due_at),
            "response_sla_hours_remaining": hours_remaining,
        }
        enriched.append(next_item)

    return enriched


def _attach_governance_payload(
    rating_dicts: list[dict[str, Any]],
    flags_by_rating: dict[str, list[dict[str, Any]]],
    actions_by_rating: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []

    for item in rating_dicts:
        key = str(item.get("rating_id") or item.get("id") or "")
        flags = flags_by_rating.get(key, [])
        actions = actions_by_rating.get(key, [])
        open_flags = [f for f in flags if _safe_text(f.get("status"), "open") == "open"]

        enriched.append(
            {
                **item,
                "flags": flags,
                "flag_count": len(flags),
                "open_flag_count": len(open_flags),
                "latest_flag": flags[0] if flags else None,
                "policy_actions": actions,
                "latest_policy_action": actions[0] if actions else None,
            }
        )

    return enriched


def _serialize_reviewable_item(item: OrderItem, order: Order, rating: Any | None = None) -> dict[str, Any]:
    product = getattr(item, "product", None)
    product_name = getattr(product, "product_name", None) or getattr(product, "name", None) or "Product"
    image_url = getattr(product, "image_url", None) if product is not None else None

    return {
        "order_id": str(getattr(order, "order_id", None) or getattr(order, "id", None) or ""),
        "order_item_id": str(getattr(item, "order_item_id", None) or getattr(item, "id", None) or ""),
        "product_id": str(getattr(item, "product_id", None) or ""),
        "product_name": product_name,
        "image_url": image_url,
        "quantity": _float(getattr(item, "quantity", None), 0.0),
        "unit": _safe_text(getattr(item, "unit", None)),
        "order_status": _normalized_status(getattr(order, "status", None)),
        "delivery_status": _normalized_status(
            getattr(item, "delivery_status", None) or getattr(order, "delivery_status", None)
        ),
        "order_date": _dt_iso(getattr(order, "order_date", None) or getattr(order, "created_at", None)),
        "verified_purchase": True,
        "already_reviewed": rating is not None,
        "existing_review": _to_dict(rating) if rating is not None else None,
    }


def _record_policy_action(
    rating_obj: Any,
    admin_id: UUID,
    action_type: str,
    rationale: Optional[str],
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """
    Record policy-action history in both the review-policy table and, if
    available, the admin audit table.

    FIX:
    Do not call AdminAuditLog(...) with keyword constructor parameters because
    the local model/type checker does not expose those names reliably.
    Instead, create the model empty and populate compatible field names safely.
    """
    rating_id_value = _uuid(getattr(rating_obj, "id", None) or getattr(rating_obj, "rating_id", None))
    safe_metadata = metadata or {}

    if ReviewPolicyAction is not None:
        policy_row = ReviewPolicyAction()
        _set_first_attr(policy_row, ("rating_id",), rating_id_value)
        _set_first_attr(policy_row, ("admin_id",), admin_id)
        _set_first_attr(policy_row, ("action_type", "action"), action_type)
        _set_first_attr(policy_row, ("action_status",), "applied")
        _set_first_attr(policy_row, ("rationale",), rationale)
        _set_first_attr(policy_row, ("metadata_json", "metadata"), safe_metadata)

        if hasattr(policy_row, "created_at") and getattr(policy_row, "created_at", None) is None:
            try:
                setattr(policy_row, "created_at", _utc_now())
            except Exception:
                pass

        db.session.add(policy_row)

    if AdminAuditLog is not None:
        admin_event = AdminAuditLog()

        has_admin = _set_first_attr(admin_event, ("admin_id", "user_id", "actor_id"), admin_id)
        has_action = _set_first_attr(admin_event, ("action", "action_type"), f"review_{action_type}")
        has_entity_type = _set_first_attr(admin_event, ("entity_type", "target_type", "resource_type"), "review")
        has_entity_id = _set_first_attr(admin_event, ("entity_id", "target_id", "resource_id"), rating_id_value)
        _set_first_attr(admin_event, ("metadata_json", "metadata", "extra_json"), safe_metadata)

        if hasattr(admin_event, "created_at") and getattr(admin_event, "created_at", None) is None:
            try:
                setattr(admin_event, "created_at", _utc_now())
            except Exception:
                pass

        # Only add the audit event if the essential attributes were set on this
        # environment's model shape.
        if has_admin and has_action and has_entity_type and has_entity_id:
            db.session.add(admin_event)


def _build_sla_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    pending = 0
    breached = 0
    on_time = 0
    late = 0
    responded = 0

    for row in rows:
        status = _safe_text(row.get("response_sla_status"), "unknown")
        if status == "needs_response":
            pending += 1
        elif status == "sla_breached":
            breached += 1
        elif status == "responded_on_time":
            on_time += 1
            responded += 1
        elif status == "responded_late":
            late += 1
            responded += 1

    return {
        "hours": RESPONSE_SLA_HOURS,
        "reviewed": len(rows),
        "responded": responded,
        "pending": pending,
        "breached": breached,
        "on_time": on_time,
        "late": late,
    }


# ----------------------------------------------------------------------------
# Routes — customer reviewable items
# ----------------------------------------------------------------------------
@ratings_bp.get("/reviewable-items", strict_slashes=False)
@require_access_token
def get_reviewable_items():
    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated user id not found", 401)

    product_filter = _uuid(request.args.get("product_id") or request.args.get("productId"))
    include_reviewed = _bool_arg(request.args.get("include_reviewed"), True)

    stmt = (
        select(OrderItem, Order)
        .join(Order, OrderItem.order_id == Order.order_id)
        .where(Order.buyer_id == current_uid)
        .order_by(Order.order_date.desc(), OrderItem.created_at.desc())
    )
    if product_filter is not None:
        stmt = stmt.where(OrderItem.product_id == product_filter)

    rows = db.session.execute(stmt).all()

    reviewed_map: dict[str, Any] = {}
    if Rating is not None:
        item_ids = [_uuid(getattr(item, "order_item_id", None) or getattr(item, "id", None)) for item, _ in rows]
        item_ids = [iid for iid in item_ids if iid is not None]

        if item_ids:
            order_item_col = _rating_order_item_col()
            user_id_col = getattr(Rating, "user_id", None)
            if order_item_col is not None and user_id_col is not None:
                try:
                    existing = db.session.scalars(
                        select(Rating)
                        .where(order_item_col.in_(item_ids))
                        .where(user_id_col == current_uid)
                    ).all()
                    for r in existing:
                        key = str(getattr(r, "order_item_id", None) or "")
                        if key:
                            reviewed_map[key] = r
                except Exception:
                    reviewed_map = {}

    items_out: list[dict[str, Any]] = []
    for item, order in rows:
        if not _is_reviewable_purchase(order, item):
            continue

        item_key = str(getattr(item, "order_item_id", None) or getattr(item, "id", None) or "")
        existing_review = reviewed_map.get(item_key)
        if existing_review is not None and not include_reviewed:
            continue

        items_out.append(_serialize_reviewable_item(item, order, existing_review))

    return jsonify({"success": True, "items": items_out})


# ----------------------------------------------------------------------------
# Routes — farmer review dashboard
# ----------------------------------------------------------------------------
@ratings_bp.get("/farmer/<string:farmer_id>", strict_slashes=False)
def farmer_ratings(farmer_id: str):
    if Rating is None:
        return _err("Ratings module not available", 501)

    fid = _uuid(farmer_id) or _uuid(request.args.get("farmerId")) or _uuid(request.args.get("farmer_id"))
    if not fid:
        return _err("Valid farmer_id is required", 400)

    days = max(1, _int(request.args.get("days"), 60))
    limit = max(1, min(_int(request.args.get("limit"), 50), 250))
    period = _safe_text(request.args.get("period"), "month").lower()
    rating_filter = _int(request.args.get("rating"), 0)
    issue_tag_filter = _normalize_issue_tag(request.args.get("issue_tag") or request.args.get("issueTag"))
    response_status_filter = _safe_text(
        request.args.get("response_status") or request.args.get("responseStatus"),
        "all",
    ).lower()
    has_comment_only = _bool_arg(request.args.get("has_comment"), False)
    verified_only = _bool_arg(request.args.get("verified_only"), False)
    product_filter = _uuid(request.args.get("product_id") or request.args.get("productId"))

    score_col_opt, created_col_opt, product_id_col_opt, _id_col, _comments_col, _rating_user_id_col = _rating_cols()
    product_pk_opt = _product_pk()
    product_owner_col_opt = _product_owner()

    if any(
        value is None
        for value in (score_col_opt, created_col_opt, product_id_col_opt, product_pk_opt, product_owner_col_opt)
    ):
        return _err("Rating/Product schema mismatch", 500)

    score_col = _required_col(score_col_opt)
    created_col = _required_col(created_col_opt)
    product_id_col = _required_col(product_id_col_opt)
    product_pk = _required_col(product_pk_opt)
    product_owner_col = _required_col(product_owner_col_opt)

    verified_col = _rating_verified_col()
    issue_tag_col = _rating_issue_tag_col()

    since = _utc_now() - timedelta(days=days)

    stmt = (
        select(Rating)
        .join(Product, product_id_col == product_pk)
        .where(product_owner_col == fid)
        .where(created_col >= since)
        .order_by(created_col.desc())
    )
    if product_filter is not None:
        stmt = stmt.where(product_id_col == product_filter)
    if rating_filter > 0:
        stmt = stmt.where(score_col == rating_filter)
    if verified_only and verified_col is not None:
        stmt = stmt.where(verified_col.is_(True))
    if issue_tag_filter is not None and issue_tag_col is not None:
        stmt = stmt.where(issue_tag_col == issue_tag_filter)

    rating_objects = db.session.scalars(stmt).all()

    rating_ids = [_uuid(getattr(r, "id", None) or getattr(r, "rating_id", None)) for r in rating_objects]
    rating_ids = [rid for rid in rating_ids if rid is not None]

    responses_by_rating = _load_public_responses_for_rating_ids(rating_ids)

    all_rows: list[dict[str, Any]] = []
    for r_obj in rating_objects:
        row = _to_dict(r_obj)
        row["product_name"] = _first_value(getattr(r_obj, "product", None), "product_name", "name", "title")
        row["customer_name"] = (
            _best_user_name(getattr(r_obj, "user", None))
            if getattr(r_obj, "user", None) is not None
            else "Customer"
        )
        buyer_loc = (
            _best_user_location(getattr(r_obj, "user", None))
            if getattr(r_obj, "user", None) is not None
            else None
        )
        if buyer_loc:
            row["buyer_location"] = buyer_loc
        all_rows.append(row)

    all_rows = _attach_public_responses(all_rows, responses_by_rating)

    effective_response_status_filter = response_status_filter
    if effective_response_status_filter not in RESPONSE_STATUS_FILTERS:
        effective_response_status_filter = "all"

    filtered_rows: list[dict[str, Any]] = []
    for row in all_rows:
        comment_text = _safe_text(row.get("comments") or row.get("comment"))
        if has_comment_only and not comment_text:
            continue
        if not _response_status_matches(
            effective_response_status_filter,
            _safe_text(row.get("response_status"), "all"),
        ):
            continue
        filtered_rows.append(row)

    ratings_list = filtered_rows[:limit]

    nums = [
        _float(r.get("rating_score") or r.get("score") or r.get("rating"), 0.0)
        for r in filtered_rows
        if (r.get("rating_score") or r.get("score") or r.get("rating")) is not None
    ]
    avg_rating = round(sum(nums) / len(nums), 2) if nums else 0.0

    distribution = {str(i): 0 for i in range(1, 6)}
    for s in nums:
        i = int(round(s))
        if 1 <= i <= 5:
            distribution[str(i)] += 1

    trend_map: dict[str, dict[str, float]] = {}
    for row in filtered_rows:
        created_at = _safe_text(row.get("created_at"))
        key = created_at[:10] if len(created_at) >= 10 else created_at
        if period == "month":
            key = created_at[:7] if len(created_at) >= 7 else key
        elif period == "year":
            key = created_at[:4] if len(created_at) >= 4 else key

        if not key:
            continue

        bucket = trend_map.setdefault(key, {"sum": 0.0, "count": 0.0})
        bucket["sum"] += _float(row.get("rating_score") or row.get("score") or row.get("rating"), 0.0)
        bucket["count"] += 1.0

    trend = [
        {
            "bucket": k,
            "avg": round(v["sum"] / v["count"], 2) if v["count"] else 0.0,
            "count": int(v["count"]),
        }
        for k, v in sorted(trend_map.items(), key=lambda item: item[0])
    ]

    available_issue_tags = sorted({
        _safe_text(row.get("issue_tag"))
        for row in all_rows
        if _safe_text(row.get("issue_tag"))
    })

    sla_summary = _build_sla_summary(filtered_rows)
    status_counts = {
        key: sum(1 for row in filtered_rows if _safe_text(row.get("response_status")) == key)
        for key in RESPONSE_STATUS_FILTERS
        if key != "all"
    }
    status_counts["all"] = len(filtered_rows)
    verified_count = sum(1 for r in filtered_rows if bool(r.get("verified_purchase")))

    return jsonify(
        {
            "success": True,
            "averageRating": avg_rating,
            "totalRatings": len(filtered_rows),
            "avg_rating": avg_rating,
            "rating_count": len(filtered_rows),
            "verified_review_count": verified_count,
            "distribution": distribution,
            "trend": trend,
            "ratings": ratings_list,
            "recent": ratings_list,
            "recent_ratings": ratings_list,
            "filters": {
                "issue_tags": available_issue_tags,
                "response_statuses": list(RESPONSE_STATUS_FILTERS),
                "applied": {
                    "days": days,
                    "rating": rating_filter,
                    "issue_tag": issue_tag_filter,
                    "response_status": effective_response_status_filter,
                    "has_comment": has_comment_only,
                    "verified_only": verified_only,
                    "product_id": str(product_filter) if product_filter else None,
                },
                "status_counts": status_counts,
            },
            "response_sla": sla_summary,
        }
    )


# ----------------------------------------------------------------------------
# Routes — public product review reads
# ----------------------------------------------------------------------------
@ratings_bp.get("/product/<string:product_id>", strict_slashes=False)
def product_ratings(product_id: str):
    if Rating is None:
        return _err("Ratings module not available", 501)

    pid = _uuid(product_id) or _uuid(request.args.get("productId")) or _uuid(request.args.get("product_id"))
    if not pid:
        return _err("Valid product_id is required", 400)

    limit = max(1, min(_int(request.args.get("limit"), 20), 100))
    _score_col_opt, created_col_opt, product_id_col_opt, _id_col, _comments_col, rating_user_id_col = _rating_cols()
    moderation_status_col = _rating_moderation_status_col()

    if product_id_col_opt is None or created_col_opt is None:
        return _err("Rating schema mismatch", 500)

    product_id_col = _required_col(product_id_col_opt)
    created_col = _required_col(created_col_opt)
    public_visibility_filter = _public_visibility_clause(moderation_status_col)

    out: list[dict[str, Any]] = []

    try:
        if rating_user_id_col is not None and _user_pk() is not None:
            u_pk = _required_col(_user_pk())

            query = (
                select(Rating, User)
                .outerjoin(User, rating_user_id_col == u_pk)
                .where(product_id_col == pid)
            )
            if public_visibility_filter is not None:
                query = query.where(public_visibility_filter)

            rows = db.session.execute(
                query.order_by(created_col.desc()).limit(limit)
            ).all()

            for r_obj, u_obj in rows:
                d = _to_dict(r_obj)
                if u_obj is not None:
                    d["buyer_name"] = _best_user_name(u_obj)
                    d["customer_name"] = d["buyer_name"]
                    loc = _best_user_location(u_obj)
                    if loc:
                        d["buyer_location"] = loc
                out.append(d)
        else:
            query = select(Rating).where(product_id_col == pid)
            if public_visibility_filter is not None:
                query = query.where(public_visibility_filter)

            items = db.session.scalars(
                query.order_by(created_col.desc()).limit(limit)
            ).all()
            out = [_to_dict(r) for r in items]
    except Exception:
        fallback_query = select(Rating).where(product_id_col == pid)
        items2 = db.session.scalars(
            fallback_query.order_by(created_col.desc()).limit(limit)
        ).all()
        out = [
            r
            for r in [_to_dict(r) for r in items2]
            if _safe_text(r.get("moderation_status"), "visible") in PUBLIC_VISIBLE_MODERATION_STATUSES
        ]

    rating_ids = [_uuid(row.get("rating_id") or row.get("id")) for row in out]
    rating_ids = [rid for rid in rating_ids if rid is not None]

    responses_by_rating = _load_public_responses_for_rating_ids(rating_ids)
    flags_by_rating = _load_flags_for_rating_ids(rating_ids)

    out = _attach_public_responses(out, responses_by_rating)
    out = _attach_governance_payload(out, flags_by_rating, {})

    return jsonify({"success": True, "ratings": out})


@ratings_bp.get("/", strict_slashes=False)
def product_ratings_from_query():
    product_id = request.args.get("product_id") or request.args.get("productId")
    if product_id:
        return product_ratings(product_id)
    return _err("product_id is required", 400)


# ----------------------------------------------------------------------------
# Routes — verified review submission
# ----------------------------------------------------------------------------
@ratings_bp.post("/", strict_slashes=False)
@require_access_token
def submit_rating():
    if Rating is None:
        return _err("Ratings module not available", 501)

    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)

    data = request.get_json(silent=True) or {}
    pid = _uuid(data.get("product_id") or data.get("productId"))
    order_id = _uuid(data.get("order_id") or data.get("orderId"))
    order_item_id = _uuid(data.get("order_item_id") or data.get("orderItemId"))

    if not pid:
        return _err("product_id is required", 400)
    if not order_item_id:
        return _err("order_item_id is required for a verified review", 400)

    score = _int(data.get("rating_score") or data.get("score") or data.get("rating"), -1)
    if score < 1 or score > 5:
        return _err("rating_score must be between 1 and 5", 400)

    comments_raw = _safe_text(data.get("comments") or data.get("comment"))
    comments = comments_raw or None

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated user id not found", 401)

    score_col_opt, _created_col, product_id_col_opt, _id_col, _comments_col, rating_user_id_col_opt = _rating_cols()
    order_id_col = _rating_order_col()
    order_item_col_opt = _rating_order_item_col()
    verified_col = _rating_verified_col()

    if product_id_col_opt is None or rating_user_id_col_opt is None or score_col_opt is None:
        return _err("Rating schema mismatch", 500)
    if order_item_col_opt is None:
        return _err("Rating schema mismatch (missing order_item_id)", 500)

    rating_user_id_col = _required_col(rating_user_id_col_opt)
    order_item_col = _required_col(order_item_col_opt)

    item = db.session.get(OrderItem, order_item_id)
    if item is None:
        return _err("Order item not found", 404)

    linked_order_id = _uuid(getattr(item, "order_id", None))
    if linked_order_id is None:
        return _err("Order linkage missing for this item", 400)

    order = db.session.get(Order, linked_order_id)
    if order is None:
        return _err("Order not found", 404)

    order_buyer_id = _uuid(getattr(order, "buyer_id", None))
    if order_buyer_id is None or order_buyer_id != current_uid:
        return _err("You can only review your own completed order items", 403)

    item_product_id = _uuid(getattr(item, "product_id", None))
    if item_product_id is None or item_product_id != pid:
        return _err("order_item_id does not belong to the supplied product_id", 400)

    if order_id is not None and linked_order_id != order_id:
        return _err("order_item_id does not belong to the supplied order_id", 400)

    if not _is_reviewable_purchase(order, item):
        return _err("Reviews are only allowed for delivered or completed order items", 400)

    product = db.session.get(Product, pid)
    if not product:
        return _err("Product not found", 404)

    existing = None
    try:
        existing = db.session.scalars(
            select(Rating)
            .where(order_item_col == order_item_id)
            .where(rating_user_id_col == current_uid)
            .limit(1)
        ).first()
    except Exception:
        existing = None

    created = existing is None
    review = existing if existing is not None else Rating()

    if created:
        if not _set_first_attr(review, ("product_id", "productId"), pid):
            return _err("Rating schema mismatch (missing product_id)", 500)
        if not _set_first_attr(review, ("user_id", "userId"), current_uid):
            return _err("Rating schema mismatch (missing user_id)", 500)
        if order_id_col is not None:
            _set_first_attr(review, ("order_id", "orderId"), linked_order_id)
        _set_first_attr(review, ("order_item_id", "orderItemId"), order_item_id)
        _set_first_attr(review, ("moderation_status",), "visible")

    if not _set_first_attr(review, ("rating_score", "score"), score):
        return _err("Rating schema mismatch (missing rating_score/score)", 500)

    _set_first_attr(review, ("comments", "comment"), comments)
    if verified_col is not None:
        _set_first_attr(review, ("verified_purchase", "verifiedPurchase"), True)

    if created and hasattr(review, "created_at") and getattr(review, "created_at", None) is None:
        try:
            setattr(review, "created_at", _utc_now())
        except Exception:
            pass

    try:
        if created:
            db.session.add(review)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return _err("Could not save review", 500)

    action = "created" if created else "updated"
    message = "Verified review submitted" if created else "Verified review updated"

    resp = jsonify(
        {
            "success": True,
            "message": message,
            "action": action,
            "rating": _to_dict(review),
        }
    )
    resp.status_code = 201 if created else 200
    return resp


# ----------------------------------------------------------------------------
# Routes — customer review flagging
# ----------------------------------------------------------------------------
@ratings_bp.post("/<string:rating_id>/flag", strict_slashes=False)
@require_access_token
def flag_rating(rating_id: str):
    if Rating is None or RatingFlag is None:
        return _err("Review flagging is not available", 501)

    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated user id not found", 401)

    rid = _uuid(rating_id)
    if rid is None:
        return _err("Valid rating_id is required", 400)

    rating_obj = db.session.get(Rating, rid)
    if rating_obj is None:
        return _err("Review not found", 404)

    data = request.get_json(silent=True) or {}
    reason_code = _normalize_flag_reason(
        data.get("reason_code") or data.get("reason") or data.get("flag_reason")
    )
    notes = _safe_text(data.get("notes") or data.get("comment")) or None

    flag = RatingFlag()
    if not _set_first_attr(flag, ("rating_id",), rid):
        return _err("RatingFlag schema mismatch (missing rating_id)", 500)
    if not _set_first_attr(flag, ("flagged_by_user_id", "user_id"), current_uid):
        return _err("RatingFlag schema mismatch (missing flagged_by_user_id)", 500)
    if not _set_first_attr(flag, ("reason_code",), reason_code):
        return _err("RatingFlag schema mismatch (missing reason_code)", 500)

    _set_first_attr(flag, ("notes",), notes)
    _set_first_attr(flag, ("status",), "open")

    if hasattr(flag, "created_at") and getattr(flag, "created_at", None) is None:
        try:
            setattr(flag, "created_at", _utc_now())
        except Exception:
            pass

    current_status = _normalize_moderation_status(getattr(rating_obj, "moderation_status", None))
    if current_status in {"visible", "published"}:
        _set_first_attr(rating_obj, ("moderation_status",), "flagged")

    try:
        db.session.add(flag)
        db.session.commit()
    except Exception:
        db.session.rollback()
        return _err("Could not submit review flag", 500)

    return jsonify(
        {
            "success": True,
            "message": "Review flagged for moderation",
            "flag": _serialize_flag(flag),
        }
    )


# ----------------------------------------------------------------------------
# Routes — farmer response workflow
# ----------------------------------------------------------------------------
@ratings_bp.post("/<string:rating_id>/response", strict_slashes=False)
@require_access_token
def add_farmer_response(rating_id: str):
    if Rating is None or RatingResponse is None:
        return _err("Ratings response workflow is not available", 501)

    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)
    if not _current_user_is_farmer(current_user):
        return _err("Only farmers can respond to reviews", 403)

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated user id not found", 401)

    rid = _uuid(rating_id)
    if rid is None:
        return _err("Valid rating_id is required", 400)

    rating_obj = db.session.get(Rating, rid)
    if rating_obj is None:
        return _err("Review not found", 404)
    if not _farmer_owns_rating(rating_obj, current_uid):
        return _err("You can only respond to reviews for your own products", 403)

    data = request.get_json(silent=True) or {}
    response_text = _safe_text(data.get("response_text") or data.get("comment") or data.get("message"))
    if not response_text:
        return _err("response_text is required", 400)
    if len(response_text) > 1200:
        return _err("response_text is too long (max 1200 characters)", 400)

    issue_tag = _normalize_issue_tag(data.get("issue_tag") or data.get("issueTag"))
    resolution_status = _normalize_resolution_status(
        data.get("resolution_status") or data.get("resolutionStatus") or "acknowledged"
    )
    is_public = _bool_arg(data.get("is_public"), True)
    now = _utc_now()

    response = RatingResponse()
    if not _set_first_attr(response, ("rating_id",), rid):
        return _err("RatingResponse schema mismatch (missing rating_id)", 500)
    if not _set_first_attr(response, ("responder_user_id", "user_id", "responder_id"), current_uid):
        return _err("RatingResponse schema mismatch (missing responder_user_id)", 500)
    if not _set_first_attr(response, ("responder_role", "role"), "farmer"):
        return _err("RatingResponse schema mismatch (missing responder_role)", 500)
    if not _set_first_attr(response, ("response_text", "comment", "message", "text"), response_text):
        return _err("RatingResponse schema mismatch (missing response_text)", 500)
    if not _set_first_attr(response, ("is_public",), is_public):
        return _err("RatingResponse schema mismatch (missing is_public)", 500)

    if hasattr(response, "created_at") and getattr(response, "created_at", None) is None:
        try:
            setattr(response, "created_at", now)
        except Exception:
            pass
    if hasattr(response, "updated_at") and getattr(response, "updated_at", None) is None:
        try:
            setattr(response, "updated_at", now)
        except Exception:
            pass

    if issue_tag is not None:
        _set_first_attr(rating_obj, ("issue_tag",), issue_tag)
    _set_first_attr(rating_obj, ("resolution_status",), resolution_status)
    if getattr(rating_obj, "first_farmer_response_at", None) is None:
        _set_first_attr(rating_obj, ("first_farmer_response_at",), now)
    _set_first_attr(rating_obj, ("last_farmer_response_at",), now)

    try:
        db.session.add(response)
        db.session.commit()
        db.session.refresh(rating_obj)
    except Exception:
        db.session.rollback()
        return _err("Could not save farmer response", 500)

    responses_by_rating = _load_public_responses_for_rating_ids([rid])
    rating_row = _attach_public_responses([_to_dict(rating_obj)], responses_by_rating)[0]

    resp = jsonify(
        {
            "success": True,
            "message": "Public farmer response saved",
            "rating": rating_row,
            "response": _serialize_response(response),
        }
    )
    resp.status_code = 201
    return resp


@ratings_bp.patch("/<string:rating_id>/workflow", strict_slashes=False)
@require_access_token
def update_farmer_review_workflow(rating_id: str):
    if Rating is None:
        return _err("Ratings workflow is not available", 501)

    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User):
        return _err("Unauthorized", 401)
    if not _current_user_is_farmer(current_user):
        return _err("Only farmers can update review workflow", 403)

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated user id not found", 401)

    rid = _uuid(rating_id)
    if rid is None:
        return _err("Valid rating_id is required", 400)

    rating_obj = db.session.get(Rating, rid)
    if rating_obj is None:
        return _err("Review not found", 404)
    if not _farmer_owns_rating(rating_obj, current_uid):
        return _err("You can only update workflow for your own product reviews", 403)

    data = request.get_json(silent=True) or {}
    issue_tag = _normalize_issue_tag(data.get("issue_tag") or data.get("issueTag"))
    resolution_status = _normalize_resolution_status(
        data.get("resolution_status")
        or data.get("resolutionStatus")
        or getattr(rating_obj, "resolution_status", "open")
    )

    if issue_tag is not None:
        _set_first_attr(rating_obj, ("issue_tag",), issue_tag)
    _set_first_attr(rating_obj, ("resolution_status",), resolution_status)

    try:
        db.session.commit()
        db.session.refresh(rating_obj)
    except Exception:
        db.session.rollback()
        return _err("Could not update review workflow", 500)

    rid_value = _uuid(getattr(rating_obj, "id", None) or getattr(rating_obj, "rating_id", None))
    responses_by_rating = _load_public_responses_for_rating_ids([rid_value] if rid_value else [])
    rating_row = _attach_public_responses([_to_dict(rating_obj)], responses_by_rating)[0]

    return jsonify(
        {
            "success": True,
            "message": "Review workflow updated",
            "rating": rating_row,
        }
    )


# ----------------------------------------------------------------------------
# Routes — admin governance
# ----------------------------------------------------------------------------
@ratings_bp.get("/admin/queue", strict_slashes=False)
@require_access_token
def admin_review_queue():
    if Rating is None:
        return _err("Ratings module not available", 501)

    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User) or not _current_user_is_admin(current_user):
        return _err("Admin access required", 403)

    days = max(1, _int(request.args.get("days"), 90))
    limit = max(1, min(_int(request.args.get("limit"), 100), 500))
    moderation_filter = _normalize_moderation_status(
        request.args.get("moderation_status") or request.args.get("status") or "flagged"
    )
    only_open_flags = _bool_arg(request.args.get("only_open_flags"), False)
    action_filter = _safe_text(request.args.get("policy_action"), "").lower()

    _score_col_opt, created_col_opt, product_id_col_opt, _id_col, _comments_col, _rating_user_id_col = _rating_cols()
    product_pk_opt = _product_pk()

    if any(value is None for value in (created_col_opt, product_id_col_opt, product_pk_opt)):
        return _err("Rating/Product schema mismatch", 500)

    created_col = _required_col(created_col_opt)
    product_id_col = _required_col(product_id_col_opt)
    product_pk = _required_col(product_pk_opt)
    moderation_col = _rating_moderation_status_col()

    since = _utc_now() - timedelta(days=days)

    stmt = (
        select(Rating)
        .join(Product, product_id_col == product_pk)
        .where(created_col >= since)
        .order_by(created_col.desc())
    )
    if moderation_col is not None and moderation_filter:
        stmt = stmt.where(moderation_col == moderation_filter)

    rating_objects = db.session.scalars(stmt).all()

    rating_ids = [_uuid(getattr(r, "id", None) or getattr(r, "rating_id", None)) for r in rating_objects]
    rating_ids = [rid for rid in rating_ids if rid is not None]

    responses_by_rating = _load_public_responses_for_rating_ids(rating_ids)
    flags_by_rating = _load_flags_for_rating_ids(rating_ids)
    actions_by_rating = _load_policy_actions_for_rating_ids(rating_ids)

    rows: list[dict[str, Any]] = []
    for rating_obj in rating_objects:
        row = _to_dict(rating_obj)
        row["product_name"] = _first_value(getattr(rating_obj, "product", None), "product_name", "name", "title")
        row["customer_name"] = (
            _best_user_name(getattr(rating_obj, "user", None))
            if getattr(rating_obj, "user", None) is not None
            else "Customer"
        )

        product_obj = getattr(rating_obj, "product", None)
        row["farmer_id"] = str(
            getattr(product_obj, "user_id", None)
            or getattr(product_obj, "farmer_id", None)
            or getattr(product_obj, "owner_id", None)
            or ""
        ) or None

        rows.append(row)

    rows = _attach_public_responses(rows, responses_by_rating)
    rows = _attach_governance_payload(rows, flags_by_rating, actions_by_rating)

    if only_open_flags:
        rows = [row for row in rows if int(row.get("open_flag_count") or 0) > 0]

    if action_filter:
        rows = [
            row
            for row in rows
            if _safe_text((row.get("latest_policy_action") or {}).get("action_type"), "").lower() == action_filter
        ]

    queue = rows[:limit]
    summary = {
        "total": len(rows),
        "flagged": sum(1 for row in rows if _safe_text(row.get("moderation_status"), "") == "flagged"),
        "under_review": sum(1 for row in rows if _safe_text(row.get("moderation_status"), "") == "under_review"),
        "hidden": sum(1 for row in rows if _safe_text(row.get("moderation_status"), "") == "hidden"),
        "removed": sum(1 for row in rows if _safe_text(row.get("moderation_status"), "") == "removed"),
        "open_flags": sum(int(row.get("open_flag_count") or 0) for row in rows),
    }

    return jsonify(
        {
            "success": True,
            "queue": queue,
            "summary": summary,
            "response_sla": _build_sla_summary(rows),
            "filters": {
                "applied": {
                    "days": days,
                    "moderation_status": moderation_filter,
                    "only_open_flags": only_open_flags,
                    "policy_action": action_filter or None,
                },
                "moderation_statuses": list(MODERATION_STATUSES),
                "policy_actions": list(POLICY_ACTIONS),
                "flag_reasons": list(FLAG_REASONS),
            },
        }
    )


@ratings_bp.get("/admin/audit", strict_slashes=False)
@require_access_token
def admin_review_audit():
    if ReviewPolicyAction is None:
        return _err("Review policy audit is not available", 501)

    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User) or not _current_user_is_admin(current_user):
        return _err("Admin access required", 403)

    limit = max(1, min(_int(request.args.get("limit"), 100), 500))
    rating_filter = _uuid(request.args.get("rating_id"))
    admin_filter = _uuid(request.args.get("admin_id"))
    action_type = _safe_text(request.args.get("action_type"), "").lower()

    stmt = select(ReviewPolicyAction).order_by(ReviewPolicyAction.created_at.desc())
    if rating_filter is not None:
        stmt = stmt.where(ReviewPolicyAction.rating_id == rating_filter)
    if admin_filter is not None:
        stmt = stmt.where(ReviewPolicyAction.admin_id == admin_filter)
    if action_type:
        stmt = stmt.where(ReviewPolicyAction.action_type == action_type)

    rows = db.session.scalars(stmt.limit(limit)).all()
    return jsonify({"success": True, "items": [_serialize_policy_action(row) for row in rows]})


@ratings_bp.post("/admin/<string:rating_id>/moderate", strict_slashes=False)
@require_access_token
def admin_moderate_review(rating_id: str):
    if Rating is None:
        return _err("Ratings module not available", 501)

    current_user = getattr(request, "current_user", None)
    if not isinstance(current_user, User) or not _current_user_is_admin(current_user):
        return _err("Admin access required", 403)

    current_uid = _current_user_id(current_user)
    if current_uid is None:
        return _err("Authenticated admin id not found", 401)

    rid = _uuid(rating_id)
    if rid is None:
        return _err("Valid rating_id is required", 400)

    rating_obj = db.session.get(Rating, rid)
    if rating_obj is None:
        return _err("Review not found", 404)

    data = request.get_json(silent=True) or {}
    action_type = _normalize_policy_action(
        data.get("action_type") or data.get("policy_action") or data.get("action")
    )
    rationale = _safe_text(data.get("rationale") or data.get("reason") or data.get("notes")) or None
    moderation_notes = _safe_text(data.get("moderation_notes") or data.get("notes")) or None
    metadata = _json_meta(data.get("metadata"))

    next_status = _safe_text(getattr(rating_obj, "moderation_status", None), "visible").lower()
    if action_type == "hide_review":
        next_status = "hidden"
    elif action_type == "remove_review":
        next_status = "removed"
    elif action_type in {"restore_review", "publish_review", "dismiss_flags"}:
        next_status = "visible"
    elif action_type == "mark_under_review":
        next_status = "under_review"

    _set_first_attr(rating_obj, ("moderation_status",), next_status)
    _set_first_attr(rating_obj, ("moderation_reason",), rationale)
    _set_first_attr(rating_obj, ("moderation_notes",), moderation_notes)
    _set_first_attr(rating_obj, ("moderated_by",), current_uid)
    _set_first_attr(rating_obj, ("moderated_at",), _utc_now())
    _set_first_attr(rating_obj, ("policy_action",), action_type)

    if RatingFlag is not None and action_type in {
        "dismiss_flags",
        "hide_review",
        "remove_review",
        "restore_review",
        "publish_review",
    }:
        try:
            flags = db.session.scalars(
                select(RatingFlag)
                .where(RatingFlag.rating_id == rid)
                .where(RatingFlag.status == "open")
            ).all()

            new_flag_status = (
                "dismissed" if action_type in {"dismiss_flags", "restore_review", "publish_review"} else "resolved"
            )

            for flag in flags:
                _set_first_attr(flag, ("status",), new_flag_status)
                _set_first_attr(flag, ("reviewed_by",), current_uid)
                _set_first_attr(flag, ("reviewed_at",), _utc_now())
        except Exception:
            pass

    try:
        _record_policy_action(
            rating_obj,
            current_uid,
            action_type,
            rationale,
            {
                "rating_id": str(rid),
                "moderation_status": next_status,
                "moderation_notes": moderation_notes,
                **metadata,
            },
        )
        db.session.commit()
        db.session.refresh(rating_obj)
    except Exception:
        db.session.rollback()
        return _err("Could not apply review moderation action", 500)

    responses_by_rating = _load_public_responses_for_rating_ids([rid])
    flags_by_rating = _load_flags_for_rating_ids([rid])
    actions_by_rating = _load_policy_actions_for_rating_ids([rid])

    row = _attach_public_responses([_to_dict(rating_obj)], responses_by_rating)
    row = _attach_governance_payload(row, flags_by_rating, actions_by_rating)[0]

    return jsonify(
        {
            "success": True,
            "message": "Review policy action applied",
            "rating": row,
        }
    )