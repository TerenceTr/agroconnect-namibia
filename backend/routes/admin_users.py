# ====================================================================
# backend/routes/admin_users.py — Admin User Management (JWT) [PYRIGHT-CLEAN]
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
# PYRIGHT/PYLANCE NOTE (ReportLab):
#   Some editors flag ReportLab imports if it's not installed in the active venv
#   or if type stubs are missing. To keep typing clean:
#     • We import reportlab ONLY inside the PDF branch at runtime.
#     • We provide TYPE_CHECKING-only imports with "ignore" hints.
# ====================================================================

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Any, Optional, TYPE_CHECKING

from flask.blueprints import Blueprint
from flask.globals import g, request
from flask.json import jsonify
from flask.wrappers import Response

from sqlalchemy import or_, select

from backend.database.db import db
from backend.models.user import ROLE_ADMIN, ROLE_CUSTOMER, ROLE_FARMER, User
from backend.utils.require_auth import require_access_token

# --------------------------------------------------------------------
# TYPE-CHECKING ONLY: Provide optional symbols so Pyright doesn't raise
# "Import could not be resolved". These do NOT execute at runtime.
# --------------------------------------------------------------------
if TYPE_CHECKING:
    # These imports may not exist in the editor environment; keep them optional.
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
# Auth helpers
# --------------------------------------------------------------------
def _current_user() -> Optional[User]:
    """
    Retrieve authenticated user from g/request context.
    (Your require_access_token decorator populates these.)
    """
    u = getattr(g, "current_user", None)
    if isinstance(u, User):
        return u

    u2 = getattr(request, "current_user", None)
    if isinstance(u2, User):
        return u2

    return None


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


def _safe_uuid(s: str) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(s))
    except Exception:
        return None


def _query_users() -> list[dict[str, Any]]:
    """
    Fetch users with optional query/filters.

    Query params:
      q      -> substring search on email/full_name
      role   -> admin|farmer|customer
      status -> active|inactive

    NOTE:
      Your User model includes deleted_at; we exclude deleted rows here.
    """
    q = (request.args.get("q") or "").strip()
    role = (request.args.get("role") or "").strip()
    status = (request.args.get("status") or "").strip()

    # Exclude soft-deleted users (DB-dump aligned model)
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

    return _json(_query_users(), 200)


@admin_users_bp.route("/users/<user_id>/status", methods=["PATCH"])
@require_access_token
def set_user_status(user_id: str) -> Response:
    """
    Toggle active/inactive for a specific user (admin-only).
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

    user.is_active = active_val
    user.updated_at = datetime.utcnow()
    db.session.commit()

    return _json(
        {"success": True, "id": str(user.id), "status": "active" if user.is_active else "inactive"},
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

        resp = Response(out, mimetype="text/csv")
        resp.headers["Content-Disposition"] = 'attachment; filename="agroconnect-users.csv"'
        return resp

    # ---------------------------
    # PDF Export (ReportLab optional)
    # ---------------------------
    try:
        # Runtime import only: prevents Pylance import errors in environments
        # where reportlab isn't installed.
        from reportlab.lib.pagesizes import A4  # type: ignore[import-not-found]
        from reportlab.pdfgen import canvas  # type: ignore[import-not-found]
    except Exception:
        # Fallback: plain text export if reportlab isn't available
        out = "\n".join(
            [
                f"{u.get('full_name')} | {u.get('email')} | {u.get('role')} | {u.get('status')}"
                for u in data
            ]
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
    for u in data[:250]:  # keep PDF readable
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

    resp = Response(pdf_bytes.getvalue(), mimetype="application/pdf")
    resp.headers["Content-Disposition"] = 'attachment; filename="agroconnect-users.pdf"'
    return resp
