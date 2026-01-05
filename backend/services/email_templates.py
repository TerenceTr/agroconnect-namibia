# ====================================================================
# backend/services/email_templates.py
# --------------------------------------------------------------------
# Email templates for consistent messaging.
# ====================================================================

from __future__ import annotations

from typing import Dict, Mapping, Tuple


EMAIL_TEMPLATES: Dict[str, Tuple[str, str]] = {
    # template_name: (subject, body_text)
    "welcome": (
        "Welcome to AgroConnect, {name}!",
        "Hi {name},\n\nWelcome to AgroConnect Namibia. Start browsing fresh produce today.\n\n— AgroConnect Team",
    ),
    "password_reset": (
        "AgroConnect password reset",
        "Your password reset code is: {code}\nThis code expires in {minutes} minutes.",
    ),
}


def render_email_template(template: str, context: Mapping[str, object]) -> tuple[str, str]:
    tpl = EMAIL_TEMPLATES.get(template)
    if tpl is None:
        raise ValueError(f"Unknown email template: {template}")

    subject_raw, body_raw = tpl
    try:
        ctx = {k: str(v) for k, v in context.items()}
        return subject_raw.format(**ctx), body_raw.format(**ctx)
    except KeyError as exc:
        missing = str(exc).strip("'")
        raise ValueError(f"Missing template key '{missing}' for email template '{template}'") from exc
