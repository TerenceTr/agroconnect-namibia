# ============================================================================
# backend/services/sms_service.py — SMS Delivery Service
# ----------------------------------------------------------------------------
# FILE ROLE:
#   • Single source of truth for outbound SMS sending in AgroConnect
#   • Keeps the rest of the backend provider-agnostic
#   • Supports raw send + templated send
#
# PROVIDERS SUPPORTED IN THIS VERSION:
#   • SMS_PROVIDER=console        -> safe development logging only
#   • SMS_PROVIDER=africastalking -> real provider delivery via Africa's Talking
#
# WHY THIS UPDATE MATTERS:
#   USSD is only useful in remote-area workflows if the farmer/customer can
#   receive follow-up confirmations after the session ends. This file now gives
#   the USSD layer a clean way to send those confirmations without hard-coding
#   provider logic into routes or business services.
# ============================================================================

from __future__ import annotations

import logging
import os
from typing import Mapping, Optional

from .africastalking_service import send_sms_via_africastalking
from .sms_templates import render_sms_template

logger = logging.getLogger("agroconnect.sms")

__all__ = ["send_sms", "send_sms_template"]


def send_sms(*, to: str, body: str, sender: Optional[str] = None) -> bool:
    """
    Send a raw SMS message.

    Returns:
      True/False only. The function never raises to callers.
    """
    try:
        provider = (os.environ.get("SMS_PROVIDER") or "console").strip().lower()
        from_name = sender or (os.environ.get("SMS_SENDER") or "AgroConnect")

        if provider == "console":
            logger.info("[SMS][CONSOLE] to=%s sender=%s body=%s", to, from_name, body)
            return True

        if provider == "africastalking":
            return send_sms_via_africastalking(
                to=to,
                body=body,
                sender=from_name,
                context={"source": "sms_service.send_sms"},
            )

        logger.warning("Unknown SMS_PROVIDER='%s' -> falling back to console", provider)
        logger.info("[SMS][CONSOLE] to=%s sender=%s body=%s", to, from_name, body)
        return True

    except Exception as exc:
        logger.exception("[SMS] send failed: %s", exc)
        return False


def send_sms_template(
    *,
    to: str,
    template: str,
    context: Mapping[str, object],
    sender: Optional[str] = None,
) -> bool:
    """
    Render and send a templated SMS.
    """
    body = render_sms_template(template, context)
    return send_sms(to=to, body=body, sender=sender)
