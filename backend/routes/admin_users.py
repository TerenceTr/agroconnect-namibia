# ====================================================================
# backend/routes/admin_users.py — Admin User Management + Audit Hooks
# --------------------------------------------------------------------
# FILE ROLE:
#   Admin endpoints powering AdminUsersPage:
#     • List users with search + filters
#     • Toggle active/inactive
#     • Export CSV/PDF (PDF uses ReportLab when available)
#
# ROUTES (Axios baseURL ends with "/api"):
#   GET   /api/admin/users?q=&role=&status=
#   PATCH /api/admin/users/<id>/status   { status: "active"|"inactive" }
#   GET   /api/admin/users/export?type=csv|pdf&q=&role=&status=
#
# UPDATED DESIGN:
#   ✅ Adds USER ACTIVITY audit events for:
#        - admin_list_users
#        - admin_export_users
#        - admin_view_users_export_pdf_fallback (when ReportLab missing)
#   ✅ Adds ADMIN GOVERNANCE audit event for:
#        - update_user_status
#   ✅ Preserves existing route shapes so AdminUsersPage does not break
#   ✅ Keeps runtime-only ReportLab import to avoid editor/type issues
#
# IMPORTANT AUDIT BOUNDARY:
#   - user_activity_events => admin browsing / report generation / list usage
#   - admin_audit_log      => privileged account state changes
# ====================================================================

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response
from sqlalchemy import or_, select

from backend.database.db import db
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User
from backend.services.audit_logger import AuditLogger
from backend.utils.require_auth import require_access_token

# --------------------------------------------------------------------
# TYPE-CHECKING ONLY: provide optional symbols so Pyright does not raise
# missing import errors when ReportLab is not installed in the editor env.
# --------------------------------------------------------------------
if TYPE_CHECKING:
    from reportlab.lib.pagesizes import A4 as _A4  # type: ignore[import-not-found]
    from reportlab.pdfgen.canvas import Canvas as _Canvas  # type: ignore[import-not-found]


admin_users_bp = Blueprint("admin_users", __name__)


# --------------------------------------------------------------------
# JSON response helpers
# --------------------------------------------------------------------
def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


# --------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------
def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    try:
        return str(value)
    except Exception:
        return ""


def _safe_uuid(value: str) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


def _request_session_id() -> Optional[str]:
    """
    Best-effort session correlation ID for user activity logging.
    """
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


# --------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------
def _current_user() -> Optional[User]:
    """
    Retrieve authenticated user from g/request context.
    (require_access_token populates these.)
    """
    u = getattr(g, "current_user", None)
    if isinstance(u, User):
        return u

    u2 = getattr(request, "current_user", None)
    if isinstance(u2, User):
        return u2

    return None


def _current_admin_uuid() -> Optional[uuid.UUID]:
    """
    Extract current admin id as a real UUID for audit writing.
    """
    u = _current_user()
    if u is None:
        return None

    raw = getattr(u, "id", None) or getattr(u, "user_id", None)
    if raw is None:
        return None

    if isinstance(raw, uuid.UUID):
        return raw

    try:
        return uuid.UUID(str(raw))
    except Exception:
        return None


def _current_admin_role_name() -> str:
    """
    Best-effort canonical role snapshot for activity logging.
    """
    u = _current_user()
    if u is None:
        return "admin"

    role_name = getattr(u, "role_name", None)
    if isinstance(role_name, str) and role_name.strip():
        return role_name.strip().lower()

    role_raw = getattr(u, "role", None)
    try:
        role_int = int(role_raw) if role_raw is not None else ROLE_ADMIN
    except Exception:
        role_int = ROLE_ADMIN

    return {
        ROLE_ADMIN: "admin",
        ROLE_FARMER: "farmer",
        ROLE_CUSTOMER: "customer",
    }.get(role_int, "admin")


def _admin_guard() -> Optional[Response]:
    """
    Ensure caller is authenticated + admin.
    Returns an error Response or None if allowed.
    """
    u = _current_user()
    if u is None:
        return _json({"success": False, "message": "Authentication required"}, 401)

    if getattr(u, "role", None) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)

    return None


# --------------------------------------------------------------------
# Audit helpers
# --------------------------------------------------------------------
def _audit_admin_view(
    *,
    action: str,
    target_type: Optional[str] = None,
    target_id: Optional[Any] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """
    Write non-governance admin usage to user_activity_events.
    """
    admin_uuid = _current_admin_uuid()
    if admin_uuid is None:
        return

    AuditLogger.log_user_activity(
        user_id=admin_uuid,
        role_name=_current_admin_role_name(),
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


def _audit_admin_governance(
    *,
    action: str,
    entity_type: str,
    entity_id: Any,
    metadata: Optional[dict[str, Any]] = None,
) -> None:
    """
    Write privileged admin decisions to admin_audit_log.
    """
    admin_uuid = _current_admin_uuid()
    if admin_uuid is None:
        return

    AuditLogger.log_admin_event(
        admin_id=admin_uuid,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        metadata=metadata or {},
    )


# --------------------------------------------------------------------
# Filter helpers
# --------------------------------------------------------------------
def _role_label(role_value: Any) -> str:
    if role_value == ROLE_ADMIN:
        return "admin"
    if role_value == ROLE_FARMER:
        return "farmer"
    if role_value == ROLE_CUSTOMER:
        return "customer"
    return "unknown"


def _role_value_from_str(s: str) -> Optional[int]:
    raw = (s or "").strip().lower()
    if raw == "admin":
        return ROLE_ADMIN
    if raw == "farmer":
        return ROLE_FARMER
    if raw == "customer":
        return ROLE_CUSTOMER
    return None


def _status_from_str(s: str) -> Optional[bool]:
    raw = (s or "").strip().lower()
    if raw == "active":
        return True
    if raw == "inactive":
        return False
    return None


def _query_users() -> list[dict[str, Any]]:
    """
    Fetch users with optional query/filters.

    Query params:
      q      -> substring search on email/full_name
      role   -> admin|farmer|customer
      status -> active|inactive

    NOTE:
      User model includes deleted_at; we exclude soft-deleted rows here.
    """
    q = (request.args.get("q") or "").strip()
    role = (request.args.get("role") or "").strip()
    status = (request.args.get("status") or "").strip()

    stmt = select(User).where(User.deleted_at.is_(None))  # type: ignore[attr-defined]

    if q:
        like = f"%{q}%"
        stmt = stmt.where(
            or_(
                User.email.ilike(like),       # type: ignore[attr-defined]
                User.full_name.ilike(like),   # type: ignore[attr-defined]
            )
        )

    role_val = _role_value_from_str(role) if role else None
    if role_val is not None:
        stmt = stmt.where(User.role == role_val)

    active_val = _status_from_str(status) if status else None
    if active_val is not None:
        stmt = stmt.where(User.is_active == active_val)

    stmt = stmt.order_by(User.created_at.desc()).limit(2000)

    users = db.session.execute(stmt).scalars().all()

    payload: list[dict[str, Any]] = []
    for u in users:
        payload.append(
            {
                "id": str(u.id),
                "full_name": u.full_name,
                "email": u.email,
                "role": _role_label(u.role),
                "role_name": _role_label(u.role),
                "status": "active" if bool(u.is_active) else "inactive",
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
        )

    return payload


# ====================================================================
# ROUTES
# ====================================================================
@admin_users_bp.route("/users", methods=["GET"])
@require_access_token
def list_users() -> Response:
    """
    List users for AdminUsersPage (admin-only).
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    payload = _query_users()

    _audit_admin_view(
        action="admin_list_users",
        target_type="user",
        metadata={
            "q": (request.args.get("q") or "").strip(),
            "role": (request.args.get("role") or "").strip(),
            "status": (request.args.get("status") or "").strip(),
            "result_count": len(payload),
        },
    )

    return _json(payload, 200)


@admin_users_bp.route("/users/<user_id>/status", methods=["PATCH"])
@require_access_token
def set_user_status(user_id: str) -> Response:
    """
    Toggle active/inactive for a specific user (admin-only).

    This is a privileged governance action and is therefore written to
    admin_audit_log, not merely user_activity_events.
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    uid = _safe_uuid(user_id)
    if uid is None:
        return _json({"success": False, "message": "Invalid user id"}, 400)

    body = request.get_json(silent=True) or {}
    status = str(body.get("status") or "").strip().lower()

    active_val = _status_from_str(status)
    if active_val is None:
        return _json({"success": False, "message": "status must be active or inactive"}, 400)

    user = db.session.execute(select(User).where(User.id == uid)).scalar_one_or_none()
    if user is None:
        return _json({"success": False, "message": "User not found"}, 404)

    before_status = "active" if bool(user.is_active) else "inactive"
    after_status = "active" if active_val else "inactive"

    user.is_active = active_val
    user.updated_at = datetime.utcnow()
    db.session.commit()

    # Governance audit: account state changed by admin
    _audit_admin_governance(
        action="update_user_status",
        entity_type="user",
        entity_id=str(user.id),
        metadata={
            "user_id": str(user.id),
            "user_email": _safe_str(getattr(user, "email", None)),
            "user_full_name": _safe_str(getattr(user, "full_name", None)),
            "user_role": _role_label(getattr(user, "role", None)),
            "before_status": before_status,
            "after_status": after_status,
            "changed_field": "is_active",
        },
    )

    # Activity audit: endpoint usage
    _audit_admin_view(
        action="admin_update_user_status",
        target_type="user",
        target_id=user.id,
        metadata={
            "user_id": str(user.id),
            "before_status": before_status,
            "after_status": after_status,
        },
    )

    return _json(
        {"success": True, "id": str(user.id), "status": after_status},
        200,
    )


@admin_users_bp.route("/users/export", methods=["GET"])
@require_access_token
def export_users() -> Response:
    """
    Export users as CSV or PDF.

    type=csv -> always available
    type=pdf -> uses reportlab if installed; otherwise falls back to plain text
    """
    guard = _admin_guard()
    if guard is not None:
        return guard

    export_type = (request.args.get("type") or "csv").lower().strip()
    if export_type not in ("csv", "pdf"):
        return _json({"success": False, "message": "type must be csv or pdf"}, 400)

    data = _query_users()

    common_metadata = {
        "export_type": export_type,
        "q": (request.args.get("q") or "").strip(),
        "role": (request.args.get("role") or "").strip(),
        "status": (request.args.get("status") or "").strip(),
        "row_count": len(data),
    }

    # ---------------------------
    # CSV Export (always works)
    # ---------------------------
    if export_type == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Full Name", "Email", "Role", "Status", "Created At"])
        for u in data:
            w.writerow(
                [
                    u.get("full_name"),
                    u.get("email"),
                    u.get("role"),
                    u.get("status"),
                    u.get("created_at"),
                ]
            )
        out = buf.getvalue().encode("utf-8")

        _audit_admin_view(
            action="admin_export_users",
            target_type="report",
            metadata={**common_metadata, "format_served": "csv"},
        )

        resp = Response(out, mimetype="text/csv")
        resp.headers["Content-Disposition"] = 'attachment; filename="agroconnect-users.csv"'
        return resp

    # ---------------------------
    # PDF Export (ReportLab optional)
    # ---------------------------
    try:
        # Runtime import only: avoids static editor/type issues if reportlab
        # is not installed in the active environment.
        from reportlab.lib.pagesizes import A4  # type: ignore[import-not-found]
        from reportlab.pdfgen import canvas  # type: ignore[import-not-found]
    except Exception:
        # Fallback: plain text export if reportlab is unavailable
        out = "\n".join(
            [
                f"{u.get('full_name')} | {u.get('email')} | {u.get('role')} | {u.get('status')}"
                for u in data
            ]
        )

        _audit_admin_view(
            action="admin_view_users_export_pdf_fallback",
            target_type="report",
            metadata={**common_metadata, "format_served": "txt_fallback"},
        )

        resp = Response(out.encode("utf-8"), mimetype="text/plain")
        resp.headers["Content-Disposition"] = 'attachment; filename="agroconnect-users.txt"'
        return resp

    pdf_bytes = io.BytesIO()
    c = canvas.Canvas(pdf_bytes, pagesize=A4)
    w_page, h_page = A4

    # Header
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, h_page - 50, "AgroConnect Namibia — Users Export")
    c.setFont("Helvetica", 10)
    c.drawString(40, h_page - 68, f"Generated: {datetime.utcnow().isoformat()}")

    # Column headers
    y = h_page - 95
    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "Full Name")
    c.drawString(210, y, "Email")
    c.drawString(420, y, "Role/Status")
    y -= 14

    # Rows
    c.setFont("Helvetica", 9)
    for u in data[:250]:  # Keep PDF readable
        if y < 60:
            c.showPage()
            y = h_page - 60
            c.setFont("Helvetica", 9)

        name = str(u.get("full_name") or "")[:28]
        email = str(u.get("email") or "")[:36]
        role_status = f"{u.get('role')} / {u.get('status')}"
        c.drawString(40, y, name)
        c.drawString(210, y, email)
        c.drawString(420, y, role_status)
        y -= 12

    c.showPage()
    c.save()

    _audit_admin_view(
        action="admin_export_users",
        target_type="report",
        metadata={**common_metadata, "format_served": "pdf"},
    )

    resp = Response(pdf_bytes.getvalue(), mimetype="application/pdf")
    resp.headers["Content-Disposition"] = 'attachment; filename="agroconnect-users.pdf"'
    return resp