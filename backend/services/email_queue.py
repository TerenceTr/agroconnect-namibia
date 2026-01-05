# ====================================================================
# backend/services/email_queue.py — Background Email Queue (Redis)
# ====================================================================
# FILE ROLE:
#   • Minimal Redis-backed queue for email dispatch.
#   • Keeps API requests fast (enqueue now, send later).
#   • Safe-by-default: never crashes the worker loop.
#
# IMPORTANT:
#   • This queue does NOT require DB tables.
#   • If Redis is unavailable, enqueue will raise (fail-fast) in dev.
# ====================================================================

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Mapping, Optional, Protocol, cast

from redis import Redis

from .mailer import send_email, send_email_template

logger = logging.getLogger("agroconnect.email.queue")

QUEUE_KEY = "queue:email"


class RedisQueue(Protocol):
    def rpush(self, name: str, *values: str) -> int: ...
    def blpop(self, keys: str, timeout: int = 0) -> Optional[tuple[str, str]]: ...


_redis = Redis.from_url(
    os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
    decode_responses=True,
)
redis: RedisQueue = cast(RedisQueue, _redis)


def enqueue_email(
    *,
    to: str,
    subject: Optional[str] = None,
    body: Optional[str] = None,
    template: Optional[str] = None,
    context: Optional[Mapping[str, object]] = None,
) -> None:
    """
    Push an email job to Redis.

    You can enqueue either:
      • (subject + body)  OR
      • (template + context)
    """
    job: Dict[str, Any] = {
        "to": to,
        "subject": subject,
        "body": body,
        "template": template,
        "context": dict(context or {}),
        "ts": int(time.time()),
    }
    redis.rpush(QUEUE_KEY, json.dumps(job))
    logger.info("[EMAIL QUEUE] enqueued to=%s template=%s", to, template)


def _process_job(job: Dict[str, Any]) -> bool:
    """Execute a single job (returns success bool)."""
    to = str(job.get("to") or "").strip()
    subject = job.get("subject")
    body = job.get("body")
    template = job.get("template")
    context = job.get("context") or {}

    if not to:
        logger.warning("[EMAIL QUEUE] job missing 'to'")
        return False

    # Prefer templated email
    if isinstance(template, str) and template.strip():
        return send_email_template(to=to, template=template, context=context if isinstance(context, dict) else {})

    # Fallback: raw subject/body
    if (
        isinstance(subject, str)
        and isinstance(body, str)
        and subject.strip()
        and body.strip()
    ):
        return send_email(to=to, subject=subject, body=body)

    logger.warning("[EMAIL QUEUE] job missing required fields")
    return False


def start_email_worker(*, poll_timeout: int = 10) -> None:
    """
    Blocking worker loop.
    Run this in a dedicated process/container.
    """
    logger.info("[EMAIL QUEUE] worker started (queue=%s)", QUEUE_KEY)

    while True:
        try:
            item = redis.blpop(QUEUE_KEY, timeout=poll_timeout)
            if not item:
                continue

            _, raw = item
            parsed = json.loads(raw)
            ok = _process_job(parsed if isinstance(parsed, dict) else {})
            logger.info("[EMAIL QUEUE] processed ok=%s", ok)

        except Exception as exc:
            logger.exception("[EMAIL QUEUE] worker error: %s", exc)
            time.sleep(1)
