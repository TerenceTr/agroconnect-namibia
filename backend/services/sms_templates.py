# ====================================================================
# backend/services/sms_templates.py — SMS Templates + Safe Renderer
# ====================================================================
# FILE ROLE:
#   • Central registry of SMS templates.
#   • Safe rendering (never throws).
#   • Supports format placeholders: "{code}", "{minutes}", etc.
# ====================================================================

from __future__ import annotations

import logging
from typing import Final, Mapping

logger = logging.getLogger("agroconnect.sms.templates")

SMS_TEMPLATES: Final[dict[str, str]] = {
    # Auth / security
    "otp": "AgroConnect OTP: {code}. Expires in {minutes} minutes.",
    "password_reset": "Reset your AgroConnect password using this code: {code}.",
    # Marketplace / orders
    "product_added": "Your product {product_name} has been added to AgroConnect.",
    "order_confirmed_farmer": "Order #{order_id} confirmed. Please prepare goods.",
    "order_received_customer": "Thank you for your order! It is being processed.",
    # System
    "system_alert": "AgroConnect alert: {message}",
}


def render_sms_template(template: str, context: Mapping[str, object]) -> str:
    """
    Render an SMS template safely.

    Returns a fallback message if:
      • template key is unknown
      • formatting fails (missing placeholders)
    """
    tpl = SMS_TEMPLATES.get(template)
    if not tpl:
        logger.warning("Unknown SMS template '%s'", template)
        return f"[AgroConnect] Message template '{template}' not found."

    try:
        return tpl.format_map(dict(context))
    except Exception as exc:
        logger.warning("Template render failed template=%s err=%s", template, exc)
        return f"[AgroConnect] Message could not be rendered (template='{template}')."
