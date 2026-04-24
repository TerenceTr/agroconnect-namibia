# ============================================================================
# backend/services/messaging.py — Buyer/Seller Messaging Service
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Shared domain service for AgroConnect in-app messaging.
#
# CURRENT SCOPE:
#   • Customer ↔ Farmer direct conversations
#   • Optional product/order context per thread
#   • Conversation listing with unread counts
#   • Message send/read helpers
#   • Message-category notification creation for recipients
# ============================================================================

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import and_, or_

from backend.database.db import db
from backend.models.message_entry import MessageEntry
from backend.models.message_thread import MessageThread
from backend.models.order import Order
from backend.models.product import Product
from backend.models.user import ROLE_CUSTOMER, ROLE_FARMER, User
from backend.services.notifications import notify_user
from backend.socketio.realtime import publish_thread_event


PREVIEW_LIMIT = 180


def _utcnow() -> datetime:
    return datetime.utcnow()


def _safe_str(value: Any, fallback: str = "") -> str:
    s = str(value or "").strip()
    return s or fallback


def _to_uuid(value: Any) -> Optional[UUID]:
    if value is None:
        return None
    if isinstance(value, UUID):
        return value
    try:
        s = str(value).strip()
        return UUID(s) if s else None
    except Exception:
        return None


def _preview(body: Any) -> str:
    text = _safe_str(body)
    if len(text) <= PREVIEW_LIMIT:
        return text
    return text[: PREVIEW_LIMIT - 1].rstrip() + "…"


def _display_name(user: Optional[User], fallback: str) -> str:
    if isinstance(user, User):
        return _safe_str(getattr(user, "full_name", None) or getattr(user, "name", None), fallback)
    return fallback


def _thread_subject(product: Optional[Product], order: Optional[Order], explicit_subject: Optional[str]) -> str:
    if _safe_str(explicit_subject):
        return _safe_str(explicit_subject)
    if isinstance(product, Product):
        name = _safe_str(getattr(product, "product_name", None) or getattr(product, "name", None), "this product")
        return f"Question about {name}"
    if isinstance(order, Order):
        order_id = getattr(order, "order_id", None) or getattr(order, "id", None)
        if order_id:
            return f"Order {order_id}"
    return "AgroConnect conversation"


def _is_customer(user: User) -> bool:
    return int(getattr(user, "role", 0) or 0) == ROLE_CUSTOMER or _safe_str(getattr(user, "role_name", None)).lower() == "customer"


def _is_farmer(user: User) -> bool:
    return int(getattr(user, "role", 0) or 0) == ROLE_FARMER or _safe_str(getattr(user, "role_name", None)).lower() == "farmer"


def _read_marker_field(thread: MessageThread, user_id: UUID) -> str:
    if user_id == thread.customer_user_id:
        return "customer_last_read_at"
    return "farmer_last_read_at"


def _participant_filter(user_id: UUID):
    return or_(MessageThread.customer_user_id == user_id, MessageThread.farmer_user_id == user_id)


def get_thread_for_user(thread_id: Any, user: User) -> Optional[MessageThread]:
    tid = _to_uuid(thread_id)
    uid = _to_uuid(getattr(user, "id", None))
    if tid is None or uid is None:
        return None
    return db.session.query(MessageThread).filter(MessageThread.thread_id == tid, _participant_filter(uid)).one_or_none()


def _unread_count_for_thread(thread: MessageThread, viewer_user_id: UUID) -> int:
    if viewer_user_id == thread.customer_user_id:
        last_read = thread.customer_last_read_at
    else:
        last_read = thread.farmer_last_read_at

    q = db.session.query(MessageEntry).filter(
        MessageEntry.thread_id == thread.thread_id,
        MessageEntry.sender_user_id != viewer_user_id,
    )
    if last_read is not None:
        q = q.filter(MessageEntry.created_at > last_read)
    return int(q.count())


def _counterpart_payload(thread: MessageThread, viewer: User) -> dict[str, Any]:
    viewer_id = _to_uuid(getattr(viewer, "id", None))
    counterpart_id = thread.farmer_user_id if viewer_id == thread.customer_user_id else thread.customer_user_id
    counterpart = db.session.get(User, counterpart_id)
    role_name = "farmer" if counterpart_id == thread.farmer_user_id else "customer"
    return {
        "user_id": str(counterpart_id),
        "full_name": _display_name(counterpart, role_name.title()),
        "role_name": role_name,
        "phone": getattr(counterpart, "phone", None) if counterpart else None,
        "email": getattr(counterpart, "email", None) if counterpart else None,
        "location": getattr(counterpart, "location", None) if counterpart else None,
    }


def _product_payload(product_id: Optional[UUID]) -> Optional[dict[str, Any]]:
    if product_id is None:
        return None
    product = db.session.get(Product, product_id)
    if not isinstance(product, Product):
        return None
    return {
        "product_id": str(getattr(product, "product_id", product_id)),
        "name": _safe_str(getattr(product, "product_name", None) or getattr(product, "name", None), "Product"),
        "image_url": getattr(product, "image_url", None),
        "category": getattr(product, "category", None),
        "price": float(getattr(product, "price", 0) or 0),
        "unit": getattr(product, "unit", None),
    }


def _serialize_thread(thread: MessageThread, viewer: User) -> dict[str, Any]:
    viewer_id = _to_uuid(getattr(viewer, "id", None))
    unread_count = _unread_count_for_thread(thread, viewer_id) if viewer_id else 0
    return {
        **thread.to_dict(),
        "counterpart": _counterpart_payload(thread, viewer),
        "product": _product_payload(thread.product_id),
        "unread_count": unread_count,
    }


def _serialize_message(row: MessageEntry) -> dict[str, Any]:
    sender = db.session.get(User, row.sender_user_id)
    return {
        **row.to_dict(),
        "sender_name": _display_name(sender, "User"),
        "sender_role_name": getattr(sender, "role_name", None) if sender else None,
    }


def _publish_realtime_message_event(thread: MessageThread, message_payload: dict[str, Any]) -> None:
    payload = {
        "thread_id": str(thread.thread_id),
        "message_id": message_payload.get("message_id"),
        "sender_user_id": message_payload.get("sender_user_id"),
        "created_at": message_payload.get("created_at"),
        "subject": _safe_str(thread.subject, "Conversation"),
    }
    publish_thread_event(
        "messages:thread-updated",
        user_ids=[thread.customer_user_id, thread.farmer_user_id],
        payload=payload,
    )


def _validate_pair(customer: User, farmer: User) -> None:
    if not _is_customer(customer):
        raise ValueError("Customer account required.")
    if not _is_farmer(farmer):
        raise ValueError("Farmer account required.")


def _resolve_context_product(product_id: Any, farmer: User) -> Optional[Product]:
    pid = _to_uuid(product_id)
    if pid is None:
        return None
    product = db.session.get(Product, pid)
    if not isinstance(product, Product):
        raise ValueError("Product not found.")
    farmer_id = _to_uuid(getattr(farmer, "id", None))
    owner_id = _to_uuid(getattr(product, "user_id", None) or getattr(product, "farmer_id", None))
    if farmer_id is not None and owner_id is not None and farmer_id != owner_id:
        raise ValueError("Selected product does not belong to this farmer.")
    return product


def _resolve_context_order(order_id: Any, customer: User, farmer: User) -> Optional[Order]:
    oid = _to_uuid(order_id)
    if oid is None:
        return None
    order = db.session.get(Order, oid)
    if not isinstance(order, Order):
        raise ValueError("Order not found.")

    buyer_id = _to_uuid(getattr(order, "buyer_id", None))
    if buyer_id and buyer_id != _to_uuid(getattr(customer, "id", None)):
        raise ValueError("Order does not belong to this customer.")

    return order


def find_existing_thread(
    *,
    customer_user_id: UUID,
    farmer_user_id: UUID,
    product_id: Optional[UUID] = None,
    order_id: Optional[UUID] = None,
) -> Optional[MessageThread]:
    q = db.session.query(MessageThread).filter(
        MessageThread.customer_user_id == customer_user_id,
        MessageThread.farmer_user_id == farmer_user_id,
    )

    if order_id is not None:
        row = q.filter(MessageThread.order_id == order_id).order_by(MessageThread.updated_at.desc()).first()
        if row is not None:
            return row

    if product_id is not None:
        row = q.filter(MessageThread.product_id == product_id).order_by(MessageThread.updated_at.desc()).first()
        if row is not None:
            return row

    return q.order_by(MessageThread.updated_at.desc()).first()


def ensure_thread(
    *,
    actor: User,
    recipient_user_id: Any,
    product_id: Any = None,
    order_id: Any = None,
    subject: Optional[str] = None,
    initial_message: Optional[str] = None,
    commit: bool = True,
) -> dict[str, Any]:
    recipient_id = _to_uuid(recipient_user_id)
    actor_id = _to_uuid(getattr(actor, "id", None))
    if recipient_id is None or actor_id is None:
        raise ValueError("Valid actor and recipient are required.")

    recipient = db.session.get(User, recipient_id)
    if not isinstance(recipient, User):
        raise ValueError("Recipient not found.")

    if _is_customer(actor) and _is_farmer(recipient):
        customer = actor
        farmer = recipient
    elif _is_farmer(actor) and _is_customer(recipient):
        customer = recipient
        farmer = actor
    else:
        raise ValueError("Messaging is currently available for customer and farmer accounts only.")

    _validate_pair(customer, farmer)
    product = _resolve_context_product(product_id, farmer) if product_id else None
    order = None
    # Order context can be added later once a dedicated ownership resolver is needed.
    if order_id:
        oid = _to_uuid(order_id)
        order = db.session.get(Order, oid) if oid is not None else None

    row = find_existing_thread(
        customer_user_id=_to_uuid(getattr(customer, "id", None)),
        farmer_user_id=_to_uuid(getattr(farmer, "id", None)),
        product_id=_to_uuid(getattr(product, "product_id", None) if product else None),
        order_id=_to_uuid(getattr(order, "order_id", None) if order else None),
    )

    now = _utcnow()
    if row is None:
        row = MessageThread(
            customer_user_id=_to_uuid(getattr(customer, "id", None)),
            farmer_user_id=_to_uuid(getattr(farmer, "id", None)),
            product_id=_to_uuid(getattr(product, "product_id", None) if product else None),
            order_id=_to_uuid(getattr(order, "order_id", None) if order else None),
            subject=_thread_subject(product, order, subject),
            last_message_at=now,
            updated_at=now,
            customer_last_read_at=now if actor_id == _to_uuid(getattr(customer, "id", None)) else None,
            farmer_last_read_at=now if actor_id == _to_uuid(getattr(farmer, "id", None)) else None,
        )
        db.session.add(row)
        db.session.flush()
    elif _safe_str(subject):
        row.subject = _safe_str(subject)

    created_message: Optional[dict[str, Any]] = None
    if _safe_str(initial_message):
        created_message = send_thread_message(row, actor, _safe_str(initial_message), commit=False)
    else:
        read_field = _read_marker_field(row, actor_id)
        setattr(row, read_field, now)
        row.updated_at = now

    if commit:
        db.session.commit()
        db.session.refresh(row)
        if created_message:
            _publish_realtime_message_event(row, created_message)

    return _serialize_thread(row, actor)


def list_threads_for_user(user: User, *, search: str = "", limit: int = 50) -> list[dict[str, Any]]:
    user_id = _to_uuid(getattr(user, "id", None))
    if user_id is None:
        return []

    safe_limit = max(1, min(int(limit or 50), 100))
    rows = (
        db.session.query(MessageThread)
        .filter(_participant_filter(user_id))
        .order_by(MessageThread.last_message_at.desc(), MessageThread.updated_at.desc())
        .limit(safe_limit)
        .all()
    )

    term = _safe_str(search).lower()
    serialized = [_serialize_thread(row, user) for row in rows]
    if not term:
        return serialized

    filtered: list[dict[str, Any]] = []
    for row in serialized:
        haystack = " ".join(
            [
                _safe_str(row.get("subject")),
                _safe_str(row.get("last_message_preview")),
                _safe_str((row.get("counterpart") or {}).get("full_name")),
                _safe_str((row.get("product") or {}).get("name")),
            ]
        ).lower()
        if term in haystack:
            filtered.append(row)
    return filtered


def get_thread_messages(thread: MessageThread, viewer: User, *, limit: int = 200) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit or 200), 500))
    rows = (
        db.session.query(MessageEntry)
        .filter(MessageEntry.thread_id == thread.thread_id)
        .order_by(MessageEntry.created_at.asc())
        .limit(safe_limit)
        .all()
    )
    return [_serialize_message(row) for row in rows]


def mark_thread_read(thread: MessageThread, viewer: User, *, commit: bool = True) -> dict[str, Any]:
    viewer_id = _to_uuid(getattr(viewer, "id", None))
    if viewer_id is None:
        raise ValueError("Viewer is required.")
    setattr(thread, _read_marker_field(thread, viewer_id), _utcnow())
    thread.updated_at = _utcnow()
    if commit:
        db.session.commit()
        db.session.refresh(thread)
    return _serialize_thread(thread, viewer)


def send_thread_message(thread: MessageThread, sender: User, body: str, *, commit: bool = True) -> dict[str, Any]:
    sender_id = _to_uuid(getattr(sender, "id", None))
    if sender_id is None:
        raise ValueError("Sender is required.")
    clean_body = _safe_str(body)
    if not clean_body:
        raise ValueError("Message body is required.")
    if sender_id not in {thread.customer_user_id, thread.farmer_user_id}:
        raise ValueError("You do not have access to this conversation.")

    now = _utcnow()
    row = MessageEntry(
        thread_id=thread.thread_id,
        sender_user_id=sender_id,
        body=clean_body,
        meta_json={},
        is_system=False,
    )
    db.session.add(row)
    db.session.flush()

    thread.last_message_preview = _preview(clean_body)
    thread.last_message_at = now
    thread.last_message_sender_id = sender_id
    thread.updated_at = now
    setattr(thread, _read_marker_field(thread, sender_id), now)

    recipient_id = thread.farmer_user_id if sender_id == thread.customer_user_id else thread.customer_user_id
    sender_name = _display_name(sender, "AgroConnect user")
    subject = _safe_str(thread.subject, "AgroConnect message")
    notification_type = "customer_message_received" if sender_id == thread.customer_user_id else "support_reply"

    notify_user(
        recipient_id,
        subject,
        _preview(clean_body),
        notification_type=notification_type,
        actor_user_id=sender_id,
        event_key=f"message-thread:{thread.thread_id}:recipient:{recipient_id}",
        data={
            "category": "messages",
            "thread_id": str(thread.thread_id),
            "sender_name": sender_name,
            "sender_user_id": str(sender_id),
            "action_label": "Open conversation",
            "product_id": str(thread.product_id) if thread.product_id else None,
            "order_id": str(thread.order_id) if thread.order_id else None,
        },
        commit=False,
    )

    message_payload = _serialize_message(row)

    if commit:
        db.session.commit()
        db.session.refresh(row)
        db.session.refresh(thread)
        message_payload = _serialize_message(row)
        _publish_realtime_message_event(thread, message_payload)

    return message_payload


def get_thread_detail(thread: MessageThread, viewer: User, *, mark_read: bool = False, limit: int = 200) -> dict[str, Any]:
    if mark_read:
        mark_thread_read(thread, viewer, commit=False)
        db.session.commit()
        db.session.refresh(thread)
    return {
        "thread": _serialize_thread(thread, viewer),
        "messages": get_thread_messages(thread, viewer, limit=limit),
    }


def get_total_unread_threads(user: User) -> int:
    rows = list_threads_for_user(user, limit=100)
    return sum(1 for row in rows if int(row.get("unread_count") or 0) > 0)
