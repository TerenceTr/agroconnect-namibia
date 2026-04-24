# ============================================================================
# backend/routes/messages.py — Buyer/Seller Messaging API
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Authenticated messaging endpoints for customer ↔ farmer conversations.
#
# ENDPOINTS:
#   GET  /api/messages/conversations
#   POST /api/messages/conversations/start
#   GET  /api/messages/conversations/<thread_id>
#   POST /api/messages/conversations/<thread_id>/messages
#   POST /api/messages/conversations/<thread_id>/read
# ============================================================================

from __future__ import annotations

from typing import Any, Optional
from uuid import UUID

from flask import Blueprint, jsonify, request

from backend.models.user import User
from backend.security import token_required
from backend.services.messaging import (
    ensure_thread,
    get_thread_detail,
    get_thread_for_user,
    get_total_unread_threads,
    list_threads_for_user,
    mark_thread_read,
    send_thread_message,
)

messages_bp = Blueprint("messages", __name__)


def _current_user() -> Optional[User]:
    user = getattr(request, "current_user", None)
    return user if isinstance(user, User) else None


def _ok(data: Any = None, *, message: str = "OK", status: int = 200):
    resp = jsonify({"success": True, "message": message, "data": data})
    resp.status_code = status
    return resp


def _err(message: str, *, status: int = 400):
    resp = jsonify({"success": False, "message": message})
    resp.status_code = status
    return resp


@messages_bp.get("/conversations")
@token_required
def list_conversations():
    user = _current_user()
    if not user:
        return _err("Unauthorized", status=401)

    rows = list_threads_for_user(
        user,
        search=request.args.get("search", ""),
        limit=request.args.get("limit", type=int) or 50,
    )
    return _ok(
        {
            "conversations": rows,
            "unread_threads": get_total_unread_threads(user),
        }
    )


@messages_bp.post("/conversations/start")
@token_required
def start_conversation():
    user = _current_user()
    if not user:
        return _err("Unauthorized", status=401)

    payload = request.get_json(silent=True) or {}
    try:
        row = ensure_thread(
            actor=user,
            recipient_user_id=payload.get("recipient_user_id") or payload.get("farmer_id") or payload.get("customer_id"),
            product_id=payload.get("product_id"),
            order_id=payload.get("order_id"),
            subject=payload.get("subject"),
            initial_message=payload.get("initial_message") or payload.get("body"),
        )
    except ValueError as exc:
        return _err(str(exc), status=400)
    except Exception:
        return _err("Failed to start conversation.", status=500)

    return _ok(row, message="Conversation ready", status=201)


@messages_bp.get("/conversations/<thread_id>")
@token_required
def get_conversation(thread_id: str):
    user = _current_user()
    if not user:
        return _err("Unauthorized", status=401)

    thread = get_thread_for_user(thread_id, user)
    if thread is None:
        return _err("Conversation not found.", status=404)

    mark_read = str(request.args.get("mark_read", "1")).strip().lower() not in {"0", "false", "no"}
    try:
        payload = get_thread_detail(thread, user, mark_read=mark_read, limit=request.args.get("limit", type=int) or 200)
    except Exception:
        return _err("Failed to load conversation.", status=500)
    return _ok(payload)


@messages_bp.post("/conversations/<thread_id>/messages")
@token_required
def post_conversation_message(thread_id: str):
    user = _current_user()
    if not user:
        return _err("Unauthorized", status=401)

    thread = get_thread_for_user(thread_id, user)
    if thread is None:
        return _err("Conversation not found.", status=404)

    payload = request.get_json(silent=True) or {}
    try:
        row = send_thread_message(thread, user, payload.get("body") or payload.get("message") or "")
    except ValueError as exc:
        return _err(str(exc), status=400)
    except Exception:
        return _err("Failed to send message.", status=500)

    return _ok(row, message="Message sent", status=201)


@messages_bp.post("/conversations/<thread_id>/read")
@token_required
def read_conversation(thread_id: str):
    user = _current_user()
    if not user:
        return _err("Unauthorized", status=401)

    thread = get_thread_for_user(thread_id, user)
    if thread is None:
        return _err("Conversation not found.", status=404)

    try:
        row = mark_thread_read(thread, user)
    except ValueError as exc:
        return _err(str(exc), status=400)
    except Exception:
        return _err("Failed to update read status.", status=500)
    return _ok(row, message="Conversation marked as read")
