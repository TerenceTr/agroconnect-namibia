# ============================================================================
# backend/services/africastalking_service.py — Africa's Talking SMS Adapter
# ----------------------------------------------------------------------------
# FILE ROLE:
#   • Encapsulates Africa's Talking outbound SMS integration
#   • Keeps provider-specific HTTP details out of business routes/services
#   • Writes best-effort SMS audit rows into the real sms_logs table shape
#
# WHY THIS VERSION FIXES YOUR ERRORS:
#   ✅ Removes the `requests` dependency so static analysis no longer reports
#      "Import requests could not be resolved from source"
#   ✅ Uses stdlib urllib instead
#   ✅ Types provider JSON as dict[str, Any] so `.get(...)` is always valid
#   ✅ Keeps all failures best-effort and never raises to callers
# ============================================================================

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from sqlalchemy import text

from backend.database.db import db

logger = logging.getLogger("agroconnect.sms.africastalking")

AFRICASTALKING_SMS_URL = "https://api.africastalking.com/version1/messaging"

__all__ = [
    "africastalking_is_configured",
    "send_sms_via_africastalking",
]


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    try:
        text_value = str(value).strip()
    except Exception:
        return default
    return text_value or default



def _digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())



def _normalize_phone(value: Any) -> str:
    """
    Normalize outbound phone numbers for Africa's Talking.

    For Namibia-oriented local numbers like 081..., send +26481... .
    If the value already looks international, keep it as +<digits>.
    """
    raw = _safe_str(value)
    if not raw:
        return ""

    if raw.startswith("+"):
        digits = _digits_only(raw)
        return f"+{digits}" if digits else ""

    digits = _digits_only(raw)
    if not digits:
        return ""

    if digits.startswith("264"):
        return f"+{digits}"

    if digits.startswith("0") and len(digits) >= 9:
        return f"+264{digits[1:]}"

    return f"+{digits}"



def africastalking_is_configured() -> bool:
    """Return True only when the required Africa's Talking credentials exist."""
    username = _safe_str(os.environ.get("AFRICASTALKING_USERNAME"))
    api_key = _safe_str(os.environ.get("AFRICASTALKING_API_KEY"))
    return bool(username and api_key)


# ---------------------------------------------------------------------------
# SMS audit logging
# ---------------------------------------------------------------------------
def _insert_sms_log(
    *,
    user_id: Optional[str],
    message: str,
    provider: str,
    status: str,
    template_name: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
    last_error: Optional[str] = None,
    sent: bool = False,
) -> None:
    """
    Insert a best-effort audit row into public.sms_logs.

    The live DB dump shows sms_logs.user_id is NOT NULL, so when no user_id is
    available we skip DB insertion and log to the server instead of causing a
    database error during development or anonymous sends.
    """
    now = datetime.utcnow()

    if not _safe_str(user_id):
        logger.info(
            "[AT SMS][AUDIT-SKIP] user_id missing status=%s provider=%s error=%s",
            status,
            provider,
            _safe_str(last_error),
        )
        return

    try:
        db.session.execute(
            text(
                """
                INSERT INTO public.sms_logs (
                    user_id,
                    message_content,
                    timestamp,
                    status,
                    template_name,
                    context,
                    provider,
                    attempt_count,
                    last_error,
                    queued_at,
                    sent_at
                )
                VALUES (
                    CAST(:user_id AS uuid),
                    :message_content,
                    :timestamp,
                    :status,
                    :template_name,
                    CAST(:context AS jsonb),
                    :provider,
                    :attempt_count,
                    :last_error,
                    :queued_at,
                    :sent_at
                )
                """
            ),
            {
                "user_id": _safe_str(user_id),
                "message_content": message,
                "timestamp": now,
                "status": status,
                "template_name": template_name,
                "context": json.dumps(context or {}, ensure_ascii=False),
                "provider": provider,
                "attempt_count": 1,
                "last_error": _safe_str(last_error) or None,
                "queued_at": now,
                "sent_at": now if sent else None,
            },
        )
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.warning("[AT SMS] Failed to insert sms_logs audit row: %s", exc)


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------
def _post_form(
    *,
    url: str,
    headers: dict[str, str],
    data: dict[str, str],
    timeout_seconds: int,
) -> tuple[int, str]:
    """
    Send a form-encoded HTTP POST using stdlib urllib.

    Returns:
      (status_code, response_text)
    """
    encoded_data = urlencode(data).encode("utf-8")
    request_obj = Request(url=url, data=encoded_data, headers=headers, method="POST")

    try:
        with urlopen(request_obj, timeout=timeout_seconds) as response:
            status_code = int(getattr(response, "status", 200))
            response_text = response.read().decode("utf-8", errors="replace")
            return status_code, response_text
    except HTTPError as exc:
        response_text = exc.read().decode("utf-8", errors="replace") if hasattr(exc, "read") else str(exc)
        return int(exc.code), response_text
    except URLError as exc:
        raise RuntimeError(f"Network error: {exc}") from exc


# ---------------------------------------------------------------------------
# Provider send
# ---------------------------------------------------------------------------
def send_sms_via_africastalking(
    *,
    to: str,
    body: str,
    sender: Optional[str] = None,
    user_id: Optional[str] = None,
    template_name: Optional[str] = None,
    context: Optional[dict[str, Any]] = None,
    timeout_seconds: int = 20,
) -> bool:
    """
    Send a single SMS through Africa's Talking.

    Returns:
      True on provider success, else False.

    NOTES:
      • The function never raises to callers.
      • We only include a sender ID when explicitly configured in the env,
        because sandbox/test accounts often reject custom sender IDs.
    """
    username = _safe_str(os.environ.get("AFRICASTALKING_USERNAME"))
    api_key = _safe_str(os.environ.get("AFRICASTALKING_API_KEY"))
    message = _safe_str(body)
    phone = _normalize_phone(to)

    if not username or not api_key:
        _insert_sms_log(
            user_id=user_id,
            message=message,
            provider="africastalking",
            status="failed",
            template_name=template_name,
            context={**(context or {}), "reason": "missing_credentials"},
            last_error="Africa's Talking credentials are missing.",
            sent=False,
        )
        logger.warning("[AT SMS] Missing Africa's Talking credentials")
        return False

    if not phone:
        _insert_sms_log(
            user_id=user_id,
            message=message,
            provider="africastalking",
            status="failed",
            template_name=template_name,
            context={**(context or {}), "reason": "invalid_phone", "to": _safe_str(to)},
            last_error="Destination phone number is invalid.",
            sent=False,
        )
        logger.warning("[AT SMS] Invalid phone number: %r", to)
        return False

    if not message:
        _insert_sms_log(
            user_id=user_id,
            message="",
            provider="africastalking",
            status="failed",
            template_name=template_name,
            context={**(context or {}), "reason": "empty_message", "to": phone},
            last_error="SMS body is empty.",
            sent=False,
        )
        logger.warning("[AT SMS] Empty message body")
        return False

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "apiKey": api_key,
    }

    payload: dict[str, str] = {
        "username": username,
        "to": phone,
        "message": message,
    }

    explicit_sender = _safe_str(os.environ.get("AFRICASTALKING_SMS_FROM")) or _safe_str(sender)
    if explicit_sender:
        payload["from"] = explicit_sender

    try:
        status_code, response_text = _post_form(
            url=AFRICASTALKING_SMS_URL,
            headers=headers,
            data=payload,
            timeout_seconds=timeout_seconds,
        )

        response_json: dict[str, Any]
        try:
            loaded = json.loads(response_text) if response_text else {}
            response_json = loaded if isinstance(loaded, dict) else {"raw": loaded}
        except Exception:
            response_json = {"raw": response_text}

        ok = 200 <= status_code < 300

        sms_message_data = response_json.get("SMSMessageData")
        recipients_info: list[dict[str, Any]] = []
        if isinstance(sms_message_data, dict):
            raw_recipients = sms_message_data.get("Recipients")
            if isinstance(raw_recipients, list):
                recipients_info = [item for item in raw_recipients if isinstance(item, dict)]

        if recipients_info:
            statuses = [_safe_str(item.get("status")).lower() for item in recipients_info]
            ok = ok and any(status in {"success", "sent", "queued", "submitted"} for status in statuses)

        _insert_sms_log(
            user_id=user_id,
            message=message,
            provider="africastalking",
            status="sent" if ok else "failed",
            template_name=template_name,
            context={
                **(context or {}),
                "to": phone,
                "request": {"username": username, "has_from": bool(explicit_sender)},
                "response": response_json,
                "http_status": status_code,
            },
            last_error=None if ok else response_text,
            sent=ok,
        )

        if ok:
            logger.info("[AT SMS] sent to=%s status=%s", phone, status_code)
        else:
            logger.warning("[AT SMS] failed to=%s status=%s body=%s", phone, status_code, response_text)

        return ok

    except Exception as exc:
        _insert_sms_log(
            user_id=user_id,
            message=message,
            provider="africastalking",
            status="failed",
            template_name=template_name,
            context={**(context or {}), "to": phone},
            last_error=str(exc),
            sent=False,
        )
        logger.exception("[AT SMS] exception while sending SMS: %s", exc)
        return False
