# ============================================================================
# backend/routes/admin_products.py — Admin Product Moderation (Admin-only)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin-only moderation endpoints for products:
#     • List products by status + search
#     • Pending queue endpoint
#     • Moderation tab counters (/stats)
#     • Product detail endpoint for review-before-decision workflow
#     • Approve / Reject actions
#     • Farmer in-app notifications when a listing is approved or rejected
#
# ROUTES (typically mounted at /api/admin):
#   GET  /products
#   GET  /products/pending
#   GET  /products/stats
#   GET  /products/<id>
#   POST /products/<id>/approve
#   POST /products/<id>/reject
#
# SETTINGS INTEGRATION:
#   ✅ Uses AUTO_PUBLISH_APPROVED_PRODUCTS to decide approved vs available
#   ✅ Uses REQUIRE_REJECTION_REASON to enforce reject reason policy
#   ✅ Uses IN_APP_NOTIFICATIONS_ENABLED before creating farmer notifications
#
# AUDIT BOUNDARY:
#   - admin_audit_log      => privileged governance actions (approve/reject)
#   - user_activity_events => page/API usage and non-governance viewing activity
# ============================================================================
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, cast

from flask.blueprints import Blueprint
from flask.globals import current_app, request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import String, and_, func, or_, select
from sqlalchemy import cast as sa_cast
from sqlalchemy.orm import Session

from backend.database.db import db
from backend.models.product import Product
from backend.models.user import User
from backend.services.audit_logger import AuditLogger
from backend.services.notifications import notify_user
from backend.utils.require_auth import require_auth

admin_products_bp = Blueprint("admin_products", __name__)


# -----------------------------------------------------------------------------
# Response + tiny utilities
# -----------------------------------------------------------------------------
def _json(payload: Dict[str, Any], status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _now() -> datetime:
    """UTC now (naive). Keep consistent with the rest of the codebase."""
    return datetime.utcnow()


def _safe_str(v: Any) -> str:
    """Safe string conversion for JSON serialization."""
    return "" if v is None else str(v)


def _cfg_bool(name: str, default: bool) -> bool:
    value = current_app.config.get(name, default)
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _int_qp(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = request.args.get(name)
    try:
        v = int(str(raw).strip())
    except Exception:
        v = int(default)
    return max(min_v, min(max_v, v))


def _parse_uuid(value: Any) -> Optional[uuid.UUID]:
    """
    Best-effort UUID parsing.
    """
    if value is None:
        return None

    if isinstance(value, uuid.UUID):
        return value

    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _status_filter(status: str) -> Tuple[str, List[str]]:
    """
    Admin UI friendly canonicalization:
      - approved tab includes both 'available' and 'approved' (legacy compat)
    """
    s = (status or "all").strip().lower()
    if s == "pending":
        return "pending", ["pending"]
    if s == "rejected":
        return "rejected", ["rejected"]
    if s in {"approved", "available"}:
        return "approved", ["available", "approved"]
    return "all", []


def _user_display_col() -> Any:
    """Prefer full_name if present, else email."""
    return User.full_name if getattr(User, "full_name", None) is not None else User.email


def _pick_user_display_value(u: User) -> str:
    """Pick a stable 'name' for UI display."""
    full_name = getattr(u, "full_name", None)
    if full_name:
        return str(full_name)
    email = getattr(u, "email", None)
    return str(email) if email else "Farmer"


def _farmer_fk_col() -> Any:
    """
    Some schemas use Product.user_id; others use Product.farmer_id.
    """
    return getattr(Product, "user_id", None) or getattr(Product, "farmer_id", None)


def _get_farmer_uuid(p: Product) -> Optional[uuid.UUID]:
    raw = getattr(p, "user_id", None) or getattr(p, "farmer_id", None)
    return _parse_uuid(raw)


def _get_farmer_id_str(p: Product) -> Optional[str]:
    uid = _get_farmer_uuid(p)
    return str(uid) if uid else None


def _get_current_admin_uuid() -> Optional[uuid.UUID]:
    current_user = getattr(request, "current_user", None)
    if current_user is None:
        return None
    return _parse_uuid(getattr(current_user, "id", None))


def _get_current_admin_role_name() -> str:
    current_user = getattr(request, "current_user", None)
    if current_user is None:
        return "admin"

    role_name = getattr(current_user, "role_name", None)
    if isinstance(role_name, str) and role_name.strip():
        return role_name.strip().lower()

    role_raw = getattr(current_user, "role", None)
    try:
        role_int = int(role_raw) if role_raw is not None else 1
    except Exception:
        role_int = 1

    return {1: "admin", 2: "farmer", 3: "customer"}.get(role_int, "admin")


def _request_session_id() -> Optional[str]:
    header_value = (
        request.headers.get("X-Session-ID")
        or request.headers.get("X-Client-Session")
        or request.headers.get("X-Device-Session")
    )
    if header_value:
        return str(header_value).strip()[:128] or None

    body = request.get_json(silent=True) or {}
    if isinstance(body, dict):
        raw = body.get("sessionId") or body.get("session_id")
        if raw is not None:
            return str(raw).strip()[:128] or None

    return None


def _client_ip() -> Optional[str]:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()[:64] or None
    return request.remote_addr or None


def _user_agent() -> Optional[str]:
    ua = request.headers.get("User-Agent")
    return ua[:256] if ua else None


def _load_user(session: Session, user_id: Any) -> Optional[User]:
    """Load a user safely from UUID or UUID-like input."""
    uid = _parse_uuid(user_id)
    if uid is None:
        return None

    try:
        return session.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    except Exception:
        return None


def _name_col() -> Any:
    """Use product_name when present; otherwise fall back to name synonym."""
    return getattr(Product, "product_name", None) or getattr(Product, "name", None)


def _get_product(session: Session, product_id: str) -> Optional[Product]:
    """
    Fetch product robustly across schema variants:
      - UUID PK on Product.id
      - string PK
      - legacy Product.product_id
    """
    pid_uuid = _parse_uuid(product_id)

    # 1) Best case: UUID primary key
    if pid_uuid is not None:
        try:
            p = session.get(Product, pid_uuid)
            if p:
                return p
        except Exception:
            pass

        try:
            p = session.get(Product, str(pid_uuid))
            if p:
                return p
        except Exception:
            pass

    # 2) Fallback: query by known columns
    clauses: List[Any] = []

    if hasattr(Product, "id"):
        clauses.append(getattr(Product, "id") == product_id)  # type: ignore[comparison-overlap]
        if pid_uuid is not None:
            clauses.append(getattr(Product, "id") == pid_uuid)  # type: ignore[comparison-overlap]

    if hasattr(Product, "product_id"):
        clauses.append(getattr(Product, "product_id") == product_id)  # type: ignore[comparison-overlap]
        if pid_uuid is not None:
            clauses.append(getattr(Product, "product_id") == pid_uuid)  # type: ignore[comparison-overlap]
            clauses.append(getattr(Product, "product_id") == str(pid_uuid))  # type: ignore[comparison-overlap]

    if not clauses:
        return None

    try:
        return session.execute(select(Product).where(or_(*clauses))).scalar_one_or_none()
    except Exception:
        return None


def _serialize_product(p: Product, farmer: Optional[User]) -> Dict[str, Any]:
    """
    Consistent JSON payload for the Admin UI.
    """
    data: Dict[str, Any]
    if hasattr(p, "to_dict"):
        data = cast(Dict[str, Any], dict(p.to_dict()))
    else:
        data = {
            "id": _safe_str(getattr(p, "id", None) or getattr(p, "product_id", None)),
            "name": _safe_str(getattr(p, "name", None) or getattr(p, "product_name", None)),
            "status": _safe_str(getattr(p, "status", None)),
        }

    data.setdefault("id", _safe_str(getattr(p, "id", None) or getattr(p, "product_id", None)))
    data.setdefault("name", _safe_str(getattr(p, "name", None) or getattr(p, "product_name", None)))
    data.setdefault("status", _safe_str(getattr(p, "status", None)))

    if farmer:
        display_name = _pick_user_display_value(farmer)
        data["farmer"] = {
            "id": _safe_str(getattr(farmer, "id", None)),
            "name": _safe_str(display_name),
            "email": _safe_str(getattr(farmer, "email", None)),
            "phone": _safe_str(getattr(farmer, "phone", None)),
            "location": _safe_str(getattr(farmer, "location", None)),
        }
        data["farmer_name"] = _safe_str(display_name)
        data["farmer_id"] = _safe_str(getattr(farmer, "id", None))
        data["farmer_email"] = _safe_str(getattr(farmer, "email", None))
        data["farmer_phone"] = _safe_str(getattr(farmer, "phone", None))
        data["farmer_location"] = _safe_str(getattr(farmer, "location", None))
    else:
        data.setdefault("farmer_id", _get_farmer_id_str(p))

    for k in (
        "moderation_changes",
        "moderation_snapshot",
        "submitted_at",
        "status_updated_at",
        "reviewed_at",
        "reviewed_by",
        "description",
        "category",
        "price",
        "quantity",
        "unit",
        "pack_size",
        "pack_unit",
        "rejection_reason",
        "image_url",
        "last_edited_at",
        "last_edited_by",
    ):
        if k not in data and hasattr(p, k):
            v = getattr(p, k)
            if isinstance(v, datetime):
                data[k] = v.isoformat()
            else:
                data[k] = v

    data.setdefault("image_path", "")
    return data


def _notify_farmer_product_review(
    *,
    product: Product,
    status: str,
    reason: Optional[str],
    actor_user_id: Optional[uuid.UUID],
) -> None:
    """
    Best-effort persisted in-app notification for the farmer.

    This is skipped entirely when in-app notifications are disabled by settings.
    """
    if not _cfg_bool("IN_APP_NOTIFICATIONS_ENABLED", True):
        return

    owner_uuid = _get_farmer_uuid(product)
    if owner_uuid is None:
        return

    normalized_status = (status or "").strip().lower()
    product_id = _safe_str(getattr(product, "id", None) or getattr(product, "product_id", None))
    product_name = _safe_str(
        getattr(product, "product_name", None) or getattr(product, "name", None) or "Product"
    )

    is_approved = normalized_status in {"approved", "available"}
    notification_type = "product_approved" if is_approved else "product_rejected"
    title = "Product listing approved" if is_approved else "Product listing rejected"

    if is_approved:
        message = f"Your product listing '{product_name}' was approved and is now visible to customers."
    else:
        message = (
            f"Your product listing '{product_name}' was rejected. "
            f"Reason: {reason or 'No reason provided.'}"
        )

    try:
        notify_user(
            owner_uuid,
            title,
            message,
            notification_type=notification_type,
            actor_user_id=actor_user_id,
            event_key=f"product_review:{product_id}:{notification_type}",
            data={
                "product_id": product_id,
                "product_name": product_name,
                "status": "available" if is_approved else "rejected",
                "rejection_reason": reason or "",
                "category": _safe_str(getattr(product, "category", None)),
                "unit": _safe_str(getattr(product, "unit", None)),
                "price": float(getattr(product, "price", 0) or 0),
                "quantity": float(getattr(product, "quantity", 0) or 0),
                "reviewed_at": _now().isoformat(),
            },
            commit=False,
        )
    except Exception:
        pass


def _list_products(
    *,
    session: Session,
    status: str,
    q: str,
    limit: int,
    offset: int,
) -> Dict[str, Any]:
    """
    Query products for Admin moderation list.
    """
    canonical, statuses = _status_filter(status)

    farmer_fk = _farmer_fk_col()
    name_col = _name_col()

    if farmer_fk is not None:
        stmt = select(Product, User).select_from(Product).outerjoin(User, User.id == farmer_fk)
        count_stmt = select(func.count()).select_from(Product).outerjoin(User, User.id == farmer_fk)
    else:
        stmt = select(Product).select_from(Product)
        count_stmt = select(func.count()).select_from(Product)

    where: List[Any] = []

    if statuses:
        where.append(Product.status.in_(statuses))

    q = (q or "").strip()
    if q:
        like = f"%{q.lower()}%"
        ors: List[Any] = []

        if name_col is not None:
            ors.append(func.lower(name_col).like(like))

        if hasattr(Product, "id"):
            ors.append(func.lower(sa_cast(getattr(Product, "id"), String)).like(like))
        if hasattr(Product, "product_id"):
            ors.append(func.lower(sa_cast(getattr(Product, "product_id"), String)).like(like))

        if farmer_fk is not None:
            ors.append(func.lower(User.email).like(like))
            ors.append(func.lower(_user_display_col()).like(like))

        if ors:
            where.append(or_(*ors))

    if where:
        stmt = stmt.where(and_(*where))
        count_stmt = count_stmt.where(and_(*where))

    total = int(session.execute(count_stmt).scalar() or 0)

    order_col = (
        getattr(Product, "updated_at", None)
        or getattr(Product, "created_at", None)
        or name_col
        or getattr(Product, "id")
    )
    stmt = stmt.order_by(order_col.desc()).limit(limit).offset(offset)

    rows = session.execute(stmt).all()

    items: List[Dict[str, Any]] = []
    for row in rows:
        p = row[0]
        u = row[1] if len(row) > 1 else None
        items.append(_serialize_product(p, u))

    return {
        "status": canonical,
        "q": q,
        "limit": limit,
        "offset": offset,
        "total": total,
        "items": items,
    }


# -----------------------------------------------------------------------------
# Audit helpers
# -----------------------------------------------------------------------------
def _audit_admin_view(
    *,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[Any] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    admin_uuid = _get_current_admin_uuid()
    if admin_uuid is None:
        return

    try:
        AuditLogger.log_user_activity(
            user_id=admin_uuid,
            role_name=_get_current_admin_role_name(),
            action=action,
            target_type=target_type,
            target_id=target_id,
            session_id=_request_session_id(),
            route=request.path,
            http_method=request.method,
            ip_address=_client_ip(),
            user_agent=_user_agent(),
            metadata_json=metadata or {},
        )
    except TypeError:
        try:
            AuditLogger.log_user_activity(
                user_id=admin_uuid,
                role_name=_get_current_admin_role_name(),
                action=action,
                target_type=target_type,
                target_id=target_id,
                session_id=_request_session_id(),
                route=request.path,
                http_method=request.method,
                ip_address=_client_ip(),
                user_agent=_user_agent(),
                metadata=metadata or {},
            )
        except Exception:
            pass
    except Exception:
        pass


def _audit_admin_governance(
    *,
    action: str,
    entity_type: str,
    entity_id: Any,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    admin_uuid = _get_current_admin_uuid()
    if admin_uuid is None:
        return

    try:
        AuditLogger.log_admin_event(
            admin_id=admin_uuid,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            metadata_json=metadata or {},
        )
    except TypeError:
        try:
            AuditLogger.log_admin_event(
                admin_id=admin_uuid,
                action=action,
                entity_type=entity_type,
                entity_id=entity_id,
                metadata=metadata or {},
            )
        except Exception:
            pass
    except Exception:
        pass


# -----------------------------------------------------------------------------
# List endpoints
# -----------------------------------------------------------------------------
@admin_products_bp.route("/products", methods=["GET"])
@require_auth("admin")
def list_products() -> Response:
    status = request.args.get("status", "all")
    q = request.args.get("q", "")
    limit = _int_qp("limit", 50, min_v=1, max_v=200)
    offset = _int_qp("offset", 0, min_v=0, max_v=1_000_000)

    data = _list_products(session=db.session, status=status, q=q, limit=limit, offset=offset)

    _audit_admin_view(
        action="admin_list_products",
        target_type="product",
        metadata={
            "status": data.get("status"),
            "q": data.get("q"),
            "limit": limit,
            "offset": offset,
            "total": data.get("total"),
        },
    )

    return _json({"success": True, "data": data})


@admin_products_bp.route("/products/pending", methods=["GET"])
@require_auth("admin")
def list_pending() -> Response:
    q = request.args.get("q", "")
    limit = _int_qp("limit", 50, min_v=1, max_v=200)
    offset = _int_qp("offset", 0, min_v=0, max_v=1_000_000)

    data = _list_products(session=db.session, status="pending", q=q, limit=limit, offset=offset)

    _audit_admin_view(
        action="admin_list_pending_products",
        target_type="product",
        metadata={
            "status": "pending",
            "q": data.get("q"),
            "limit": limit,
            "offset": offset,
            "total": data.get("total"),
        },
    )

    return _json({"success": True, "data": data})


@admin_products_bp.route("/products/stats", methods=["GET"])
@require_auth("admin")
def stats() -> Response:
    session: Session = db.session

    pending = int(
        session.execute(
            select(func.count()).select_from(Product).where(Product.status == "pending")
        ).scalar()
        or 0
    )
    rejected = int(
        session.execute(
            select(func.count()).select_from(Product).where(Product.status == "rejected")
        ).scalar()
        or 0
    )
    approved = int(
        session.execute(
            select(func.count()).select_from(Product).where(Product.status.in_(["available", "approved"]))
        ).scalar()
        or 0
    )
    total = int(session.execute(select(func.count()).select_from(Product)).scalar() or 0)

    payload = {
        "pending": pending,
        "approved": approved,
        "rejected": rejected,
        "total": total,
    }

    _audit_admin_view(
        action="admin_view_product_stats",
        target_type="report",
        metadata=payload,
    )

    return _json({"success": True, "data": payload})


# -----------------------------------------------------------------------------
# Detail endpoint
# -----------------------------------------------------------------------------
@admin_products_bp.route("/products/<string:product_id>", methods=["GET"])
@require_auth("admin")
def get_product_detail(product_id: str) -> Response:
    session: Session = db.session

    product = _get_product(session, product_id)
    if not product:
        return _json({"success": False, "error": "Product not found"}, 404)

    farmer = _load_user(session, _get_farmer_uuid(product))
    serialized = _serialize_product(product, farmer)

    _audit_admin_view(
        action="admin_view_product_detail",
        target_type="product",
        target_id=_parse_uuid(serialized.get("id")),
        metadata={
            "product_id": serialized.get("id"),
            "product_name": serialized.get("name"),
            "status": serialized.get("status"),
            "farmer_id": serialized.get("farmer_id"),
        },
    )

    return _json({"success": True, "data": serialized})


# -----------------------------------------------------------------------------
# Action endpoints (approve / reject)
# -----------------------------------------------------------------------------
@admin_products_bp.route("/products/<string:product_id>/approve", methods=["POST"])
@require_auth("admin")
def approve(product_id: str) -> Response:
    session: Session = db.session

    p = _get_product(session, product_id)
    if not p:
        return _json({"success": False, "error": "Product not found"}, 404)

    admin_uuid = _get_current_admin_uuid()
    farmer_uuid = _get_farmer_uuid(p)

    before_status = _safe_str(getattr(p, "status", None))
    before_reason = _safe_str(getattr(p, "rejection_reason", None))
    product_uuid = _parse_uuid(getattr(p, "id", None) or getattr(p, "product_id", None))
    product_id_str = _safe_str(getattr(p, "id", None) or getattr(p, "product_id", None))
    product_name = _safe_str(getattr(p, "product_name", None) or getattr(p, "name", None))

    # -------------------------------------------------------------------------
    # Settings-driven approval policy:
    #   - if AUTO_PUBLISH_APPROVED_PRODUCTS = true  -> available
    #   - otherwise                                 -> approved
    # This lets admins approve a product without necessarily publishing it
    # immediately when a stricter moderation workflow is desired.
    # -------------------------------------------------------------------------
    approved_status = "available" if _cfg_bool("AUTO_PUBLISH_APPROVED_PRODUCTS", True) else "approved"

    setattr(p, "_moderation_actor", "admin")
    p.status = approved_status

    if hasattr(p, "reviewed_at"):
        p.reviewed_at = _now()  # type: ignore[assignment]
    if hasattr(p, "reviewed_by"):
        p.reviewed_by = admin_uuid  # type: ignore[assignment]
    if hasattr(p, "rejection_reason"):
        p.rejection_reason = None  # type: ignore[assignment]
    if hasattr(p, "status_updated_at"):
        p.status_updated_at = _now()  # type: ignore[assignment]

    if hasattr(p, "build_moderation_snapshot"):
        try:
            p.moderation_snapshot = p.build_moderation_snapshot()  # type: ignore[assignment]
        except Exception:
            pass

    if hasattr(p, "moderation_changes"):
        p.moderation_changes = None  # type: ignore[assignment]

    session.add(p)

    _notify_farmer_product_review(
        product=p,
        status=approved_status,
        reason=None,
        actor_user_id=admin_uuid,
    )

    session.commit()

    _audit_admin_governance(
        action="approve_product",
        entity_type="product",
        entity_id=product_id_str,
        metadata={
            "product_id": product_id_str,
            "product_name": product_name,
            "farmer_id": str(farmer_uuid) if farmer_uuid else None,
            "before_status": before_status,
            "after_status": approved_status,
            "before_rejection_reason": before_reason or None,
            "after_rejection_reason": None,
            "decision": "approved",
        },
    )

    _audit_admin_view(
        action="admin_approve_product",
        target_type="product",
        target_id=product_uuid,
        metadata={
            "product_id": product_id_str,
            "product_name": product_name,
            "decision": "approved",
            "after_status": approved_status,
        },
    )

    farmer = _load_user(session, farmer_uuid)
    return _json({"success": True, "data": _serialize_product(p, farmer)})


@admin_products_bp.route("/products/<string:product_id>/reject", methods=["POST"])
@require_auth("admin")
def reject(product_id: str) -> Response:
    body = request.get_json(silent=True) or {}
    reason = str(body.get("reason") or "").strip()

    # -------------------------------------------------------------------------
    # Settings-driven rejection policy:
    #   REQUIRE_REJECTION_REASON controls whether the API enforces a reason.
    # -------------------------------------------------------------------------
    if _cfg_bool("REQUIRE_REJECTION_REASON", True) and not reason:
        return _json({"success": False, "error": "Rejection reason is required"}, 400)

    session: Session = db.session

    p = _get_product(session, product_id)
    if not p:
        return _json({"success": False, "error": "Product not found"}, 404)

    admin_uuid = _get_current_admin_uuid()
    farmer_uuid = _get_farmer_uuid(p)

    before_status = _safe_str(getattr(p, "status", None))
    before_reason = _safe_str(getattr(p, "rejection_reason", None))
    product_uuid = _parse_uuid(getattr(p, "id", None) or getattr(p, "product_id", None))
    product_id_str = _safe_str(getattr(p, "id", None) or getattr(p, "product_id", None))
    product_name = _safe_str(getattr(p, "product_name", None) or getattr(p, "name", None))

    setattr(p, "_moderation_actor", "admin")
    p.status = "rejected"

    if hasattr(p, "reviewed_at"):
        p.reviewed_at = _now()  # type: ignore[assignment]
    if hasattr(p, "reviewed_by"):
        p.reviewed_by = admin_uuid  # type: ignore[assignment]
    if hasattr(p, "rejection_reason"):
        p.rejection_reason = reason or None  # type: ignore[assignment]
    if hasattr(p, "status_updated_at"):
        p.status_updated_at = _now()  # type: ignore[assignment]

    session.add(p)

    _notify_farmer_product_review(
        product=p,
        status="rejected",
        reason=reason or None,
        actor_user_id=admin_uuid,
    )

    session.commit()

    _audit_admin_governance(
        action="reject_product",
        entity_type="product",
        entity_id=product_id_str,
        metadata={
            "product_id": product_id_str,
            "product_name": product_name,
            "farmer_id": str(farmer_uuid) if farmer_uuid else None,
            "before_status": before_status,
            "after_status": "rejected",
            "before_rejection_reason": before_reason or None,
            "after_rejection_reason": reason or None,
            "decision": "rejected",
        },
    )

    _audit_admin_view(
        action="admin_reject_product",
        target_type="product",
        target_id=product_uuid,
        metadata={
            "product_id": product_id_str,
            "product_name": product_name,
            "decision": "rejected",
            "reason": reason or None,
        },
    )

    farmer = _load_user(session, farmer_uuid)
    return _json({"success": True, "data": _serialize_product(p, farmer)})


# -----------------------------------------------------------------------------
# Optional route aliases
# -----------------------------------------------------------------------------
@admin_products_bp.route("/<string:product_id>", methods=["GET"])
@require_auth("admin")
def get_product_detail_alias(product_id: str) -> Response:
    return get_product_detail(product_id)


@admin_products_bp.route("/<string:product_id>/approve", methods=["POST"])
@require_auth("admin")
def approve_alias(product_id: str) -> Response:
    return approve(product_id)


@admin_products_bp.route("/<string:product_id>/reject", methods=["POST"])
@require_auth("admin")
def reject_alias(product_id: str) -> Response:
    return reject(product_id)