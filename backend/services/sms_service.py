# ====================================================================
# backend/services/sms_service.py — SMS Delivery Service
# ====================================================================
# FILE ROLE:
#   • Single source of truth for sending SMS (provider-agnostic).
#   • Offers raw send + templated send.
#   • Default provider is console (safe for development).
# ====================================================================

from __future__ import annotations

import logging
import os
from typing import Mapping, Optional

from .sms_templates import render_sms_template

logger = logging.getLogger("agroconnect.sms")

__all__ = ["send_sms", "send_sms_template"]


def send_sms(*, to: str, body: str, sender: Optional[str] = None) -> bool:
    """
    Send a raw SMS message.

    Providers:
      • SMS_PROVIDER=console (default) -> logs to console
      • Extend with Twilio/Africa'sTalking later

    Returns:
      True/False (never raises)
    """
    try:
        provider = (os.environ.get("SMS_PROVIDER") or "console").lower()
        from_name = sender or (os.environ.get("SMS_SENDER") or "AgroConnect")

        if provider == "console":
            logger.info("[SMS][CONSOLE] to=%s sender=%s body=%s", to, from_name, body)
            return True

        # Future:
        # if provider == "twilio": ...

        logger.warning("Unknown SMS_PROVIDER='%s' -> falling back to console", provider)
        logger.info("[SMS][CONSOLE] to=%s sender=%s body=%s", to, from_name, body)
        return True

    except Exception as exc:
        logger.exception("[SMS] send failed: %s", exc)
        return False


def send_sms_template(*, to: str, template: str, context: Mapping[str, object], sender: Optional[str] = None) -> bool:
    """
    Render and send a templated SMS.
    """
    body = render_sms_template(template, context)
    return send_sms(to=to, body=body, sender=sender)
