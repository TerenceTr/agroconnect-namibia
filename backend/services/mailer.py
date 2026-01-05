# ====================================================================
# backend/services/mailer.py — SMTP Mailer (HARDENED)
# ====================================================================
# FILE ROLE:
#   • Send emails via SMTP when configured.
#   • Safe console fallback when SMTP not configured (dev friendly).
#   • Never raises to callers (returns bool).
# ====================================================================

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Mapping, Optional, TypedDict

from .email_templates import render_email_template

logger = logging.getLogger("agroconnect.mailer")


class SMTPConfig(TypedDict, total=False):
    host: Optional[str]
    port: Optional[int]
    user: Optional[str]
    password: Optional[str]
    use_tls: bool
    use_ssl: bool


class SMTPConfigStrict(TypedDict):
    host: str
    port: int
    user: Optional[str]
    password: Optional[str]
    use_tls: bool
    use_ssl: bool


def _smtp_config() -> SMTPConfig:
    port_raw = os.environ.get("SMTP_PORT")
    return {
        "host": os.environ.get("SMTP_HOST"),
        "port": int(port_raw) if port_raw else None,
        "user": os.environ.get("SMTP_USER"),
        "password": os.environ.get("SMTP_PASS"),
        "use_tls": (os.environ.get("SMTP_TLS", "true").lower() in ("1", "true", "yes")),
        "use_ssl": (os.environ.get("SMTP_SSL", "false").lower() in ("1", "true", "yes")),
    }


def _require_smtp(cfg: SMTPConfig) -> Optional[SMTPConfigStrict]:
    host = cfg.get("host")
    port = cfg.get("port")
    if not host or not port:
        return None
    return {
        "host": host,
        "port": port,
        "user": cfg.get("user"),
        "password": cfg.get("password"),
        "use_tls": cfg.get("use_tls", True),
        "use_ssl": cfg.get("use_ssl", False),
    }


def send_email(to: str, subject: str, body: str, html: Optional[str] = None) -> bool:
    """
    Low-level email send.
    Returns:
      True  -> sent (or console fallback)
      False -> failed
    """
    try:
        smtp = _require_smtp(_smtp_config())

        # ---------------- Console fallback ----------------
        if smtp is None:
            logger.info("[EMAIL][CONSOLE] To=%s Subject=%s\n%s", to, subject, body)
            if html:
                logger.info("[EMAIL][CONSOLE][HTML]\n%s", html)
            return True

        msg = EmailMessage()
        msg["From"] = os.environ.get("EMAIL_FROM", smtp["user"] or "no-reply@agroconnect.local")
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        if html:
            msg.add_alternative(html, subtype="html")

        # ---------------- Connect ----------------
        if smtp["use_ssl"]:
            server = smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=15)
        else:
            server = smtplib.SMTP(smtp["host"], smtp["port"], timeout=15)
            server.ehlo()
            if smtp["use_tls"]:
                server.starttls()
                server.ehlo()

        # ---------------- Auth (optional) ----------------
        if smtp["user"] and smtp["password"]:
            server.login(smtp["user"], smtp["password"])

        server.send_message(msg)
        server.quit()

        logger.info("[EMAIL] sent ok to=%s", to)
        return True

    except Exception as exc:
        logger.exception("[EMAIL] send failed to=%s err=%s", to, exc)
        return False


def send_email_template(*, to: str, template: str, context: Mapping[str, object]) -> bool:
    """
    Render + send a templated email.
    """
    subject, body = render_email_template(template, context)
    return send_email(to=to, subject=subject, body=body)
