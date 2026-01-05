# ====================================================================
# backend/services/sms_queue.py — Background SMS Queue (Redis + DB Audit)
# ====================================================================
# FILE ROLE:
#   • Enqueue SMS jobs to Redis (fast API response)
#   • Persist SMS lifecycle events in sms_logs (audit trail)
#   • Worker consumes Redis jobs and sends via sms_service
#
# DB MODEL ALIGNMENT (SmsLog):
#   We ONLY write fields that exist:
#     - SmsLog.id
#     - SmsLog.user_id
#     - SmsLog.phone_number
#     - SmsLog.message
#     - SmsLog.status
#     - SmsLog.timestamp
#
# KEY DESIGN CHOICES:
#   • Avoid SmsLog(**kwargs) to keep Pyright happy (SQLAlchemy __init__ is dynamic)
#   • Safe UUID conversion for user_id and sms_id
#   • Never crashes worker loop (always catches + logs)
#   • Use sms_log.utc_now() as the single timestamp helper
# ====================================================================

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from typing import Any, Dict, Mapping, Optional, Protocol, cast

from redis import Redis

from backend.database.db import db
from backend.models.sms_log import SmsLog, utc_now

from .sms_service import send_sms, send_sms_template

logger = logging.getLogger("agroconnect.sms.queue")

QUEUE_KEY = "queue:sms"


# --------------------------------------------------------------------
# Protocol keeps Pyright happy while allowing a real Redis client
# --------------------------------------------------------------------
class RedisQueue(Protocol):
    def rpush(self, name: str, *values: str) -> int: ...
    def blpop(self, keys: str, timeout: int = 0) -> Optional[tuple[str, str]]: ...


# Configure Redis (decode_responses=True returns str instead of bytes)
_redis = Redis.from_url(
    os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    decode_responses=True,
)
redis: RedisQueue = cast(RedisQueue, _redis)


def _to_uuid(value: Any) -> Optional[uuid.UUID]:
    """Best-effort UUID parsing."""
    try:
        return uuid.UUID(str(value))
    except Exception:
        return None


# ====================================================================
# ENQUEUE
# ====================================================================
def enqueue_sms(
    *,
    to: str,
    body: Optional[str] = None,
    template: Optional[str] = None,
    context: Optional[Mapping[str, object]] = None,
    sender: Optional[str] = None,
    user_id: Optional[str] = None,
) -> str:
    """
    Enqueue an SMS job and persist an audit row.

    Returns:
        sms_id (string UUID) of the SmsLog row.

    NOTE:
      Our SmsLog table is intentionally simple (DB-aligned).
      We store the final resolved message text in SmsLog.message.
      Template/context are used for sending, but not stored as separate columns.
    """
    to = (to or "").strip()
    if not to:
        raise ValueError("enqueue_sms: 'to' is required")

    # Determine message to store/send
    message_text = ""
    if isinstance(template, str) and template.strip():
        # Store a readable audit message for template sends
        message_text = f"[template:{template.strip()}] {json.dumps(dict(context or {}), ensure_ascii=False)}"
    else:
        message_text = str(body or "").strip()

    if not message_text:
        raise ValueError("enqueue_sms: 'body' or 'template' is required")

    user_uuid = _to_uuid(user_id) if user_id else None

    # ---------------- Persist audit row (DB-aligned fields only) ----------------
    log = SmsLog()
    log.user_id = user_uuid
    log.phone_number = to
    log.message = message_text
    log.status = "queued"
    log.timestamp = utc_now()

    db.session.add(log)
    db.session.commit()
    db.session.refresh(log)

    # ---------------- Push job to Redis ----------------
    job: Dict[str, Any] = {
        "sms_id": str(log.id),
        "to": to,
        "body": body,
        "template": template,
        "context": dict(context or {}),
        "sender": sender,
    }

    try:
        redis.rpush(QUEUE_KEY, json.dumps(job))
        logger.info("[SMS QUEUE] enqueued sms_id=%s to=%s", log.id, to)
    except Exception as exc:
        # If Redis is down, mark audit row as failed (so admins can see it)
        try:
            log.status = "failed"
            log.timestamp = utc_now()
            # No last_error column exists in your SmsLog schema, so we can only log.
            db.session.commit()
        except Exception:
            db.session.rollback()

        logger.exception("[SMS QUEUE] Redis enqueue failed sms_id=%s err=%s", log.id, exc)

    return str(log.id)


# ====================================================================
# WORKER: Process a single job
# ====================================================================
def _process_job(job: Dict[str, Any]) -> bool:
    """
    Consume a single Redis job and update SmsLog lifecycle.

    Updates:
      • status: queued -> sent/failed
      • timestamp: updated on completion
    """
    sms_uuid = _to_uuid(job.get("sms_id"))
    if sms_uuid is None:
        logger.warning("[SMS QUEUE] job missing/invalid sms_id: %r", job.get("sms_id"))
        return False

    log_row = db.session.get(SmsLog, sms_uuid)
    if not log_row:
        logger.warning("[SMS QUEUE] sms_log not found: %s", sms_uuid)
        return False

    try:
        to = str(job.get("to") or "").strip()
        sender = job.get("sender")
        body = job.get("body")
        template = job.get("template")
        ctx = job.get("context") or {}

        if not to:
            raise ValueError("Missing destination number")

        # ---------------- Send ----------------
        ok = False
        if isinstance(template, str) and template.strip():
            ok = send_sms_template(
                to=to,
                template=template.strip(),
                context=ctx if isinstance(ctx, dict) else {},
                sender=sender if isinstance(sender, str) else None,
            )
        elif isinstance(body, str) and body.strip():
            ok = send_sms(
                to=to,
                body=body.strip(),
                sender=sender if isinstance(sender, str) else None,
            )
        else:
            raise ValueError("Missing body and template")

        # ---------------- Lifecycle (DB-aligned updates) ----------------
        log_row.status = "sent" if ok else "failed"
        log_row.timestamp = utc_now()

        db.session.commit()
        return ok

    except Exception as exc:
        # No last_error column exists in your SmsLog schema.
        # We log the error and mark the row as failed.
        try:
            log_row.status = "failed"
            log_row.timestamp = utc_now()
            db.session.commit()
        except Exception:
            db.session.rollback()

        logger.exception("[SMS QUEUE] failed sms_id=%s err=%s", sms_uuid, exc)
        return False


# ====================================================================
# WORKER LOOP
# ====================================================================
def start_sms_worker(*, poll_timeout: int = 10) -> None:
    """
    Blocking Redis worker loop.
    Safe to run multiple instances.
    """
    logger.info("[SMS QUEUE] worker started (queue=%s)", QUEUE_KEY)

    while True:
        try:
            item = redis.blpop(QUEUE_KEY, timeout=poll_timeout)
            if not item:
                continue

            _, raw = item
            payload = json.loads(raw)
            _process_job(payload if isinstance(payload, dict) else {})

        except Exception as exc:
            logger.exception("[SMS QUEUE] worker crash: %s", exc)
            time.sleep(1)
