# ====================================================================
# backend/services/mailer.py — SMTP Mailer (SMTP-AWARE)
# ====================================================================
# FILE ROLE:
#   • Send emails via SMTP when configured.
#   • Provide explicit console-fallback reporting in development.
#   • Never raise to callers.
#
# IMPORTANT IN THIS VERSION:
#   • FIXES Pyright/import issue by importing Flask helpers from typed
#     submodules instead of the flask top-level package:
#         - current_app  -> flask.globals
#         - has_app_context -> flask.ctx
#   • send_email_result(...) distinguishes real SMTP delivery from console/dev
#     fallback. This prevents higher-level routes from claiming a real inbox
#     delivery happened when SMTP is missing.
#   • send_email(...) remains backward-compatible for older callers that only
#     expect a boolean.
# ====================================================================

from __future__ import annotations

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Mapping, Optional, TypedDict

# --------------------------------------------------------------------
# IMPORTANT FOR TYPE CHECKERS:
# Import Flask helpers from typed submodules instead of:
#   from flask import current_app, has_app_context
# This avoids the Pyright error:
#   "has_app_context" is unknown import symbol
# --------------------------------------------------------------------
from flask.ctx import has_app_context
from flask.globals import current_app

from .email_templates import render_email_template

logger = logging.getLogger("agroconnect.mailer")


class SMTPConfig(TypedDict, total=False):
    """
    Loose SMTP config shape while values are still being resolved.
    """

    host: Optional[str]
    port: Optional[int]
    user: Optional[str]
    password: Optional[str]
    use_tls: bool
    use_ssl: bool
    email_from: Optional[str]


class SMTPConfigStrict(TypedDict):
    """
    Fully usable SMTP config shape after validation.
    """

    host: str
    port: int
    user: Optional[str]
    password: Optional[str]
    use_tls: bool
    use_ssl: bool
    email_from: str


class EmailSendResult(TypedDict, total=False):
    """
    Structured delivery result returned to callers that need to know
    whether a message was really delivered via SMTP or only accepted in
    development fallback mode.
    """

    ok: bool
    accepted: bool
    delivered: bool
    mode: str
    reason: str
    smtp_configured: bool
    to: str
    subject: str


# ----------------------------------------------------------------------------
# Config helpers
# ----------------------------------------------------------------------------
def _boolish(value: object, default: bool = False) -> bool:
    """
    Parse boolean-like values safely from config / environment sources.
    """
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _intish(value: object, default: Optional[int] = None) -> Optional[int]:
    """
    Parse integer-like values safely from config / environment sources.
    """
    if value in (None, ""):
        return default
    try:
        return int(str(value).strip())
    except Exception:
        return default


def _cfg(name: str, env_name: Optional[str] = None, default: object = None) -> object:
    """
    Resolve configuration in this order:
      1) Flask current_app.config (when app context exists)
      2) Environment variable
      3) Provided default

    WHY:
    This keeps the mailer usable both inside Flask request/app contexts and in
    places where only environment variables are available.
    """
    if has_app_context():
        configured = current_app.config.get(name, None)
        if configured not in (None, ""):
            return configured

    env_key = env_name or name
    env_value = os.environ.get(env_key)
    if env_value not in (None, ""):
        return env_value

    return default


# ----------------------------------------------------------------------------
# SMTP resolution
# ----------------------------------------------------------------------------
def _smtp_config() -> SMTPConfig:
    """
    Build the raw SMTP configuration from app config / environment.
    """
    return {
        "host": str(_cfg("SMTP_HOST", "SMTP_HOST", "") or "").strip() or None,
        "port": _intish(_cfg("SMTP_PORT", "SMTP_PORT", None), None),
        "user": str(_cfg("SMTP_USER", "SMTP_USER", "") or "").strip() or None,
        "password": str(_cfg("SMTP_PASS", "SMTP_PASS", "") or "").strip() or None,
        "use_tls": _boolish(_cfg("SMTP_TLS", "SMTP_TLS", True), True),
        "use_ssl": _boolish(_cfg("SMTP_SSL", "SMTP_SSL", False), False),
        "email_from": str(_cfg("EMAIL_FROM", "EMAIL_FROM", "") or "").strip() or None,
    }


def _require_smtp(cfg: SMTPConfig) -> Optional[SMTPConfigStrict]:
    """
    Convert the loose config into a strict SMTP config only if the minimum
    required fields are present.
    """
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
        "email_from": cfg.get("email_from") or cfg.get("user") or "no-reply@agroconnect.local",
    }


# ----------------------------------------------------------------------------
# Public email senders
# ----------------------------------------------------------------------------
def send_email_result(
    to: str,
    subject: str,
    body: str,
    html: Optional[str] = None,
) -> EmailSendResult:
    """
    Low-level email send with explicit result reporting.

    Result modes:
      - smtp              -> real SMTP delivery was attempted and succeeded
      - console_fallback  -> SMTP is not configured, content only logged locally
      - failed            -> SMTP send failed
    """
    clean_to = str(to or "").strip()
    clean_subject = str(subject or "").strip()
    clean_body = str(body or "")

    smtp = _require_smtp(_smtp_config())

    # ------------------------------------------------------------------------
    # Development-safe fallback:
    # We log email content locally when SMTP is not configured, but we do NOT
    # claim that a real inbox delivery happened.
    # ------------------------------------------------------------------------
    if smtp is None:
        logger.warning(
            "[EMAIL][CONSOLE-FALLBACK] SMTP not configured. To=%s Subject=%s\n%s",
            clean_to,
            clean_subject,
            clean_body,
        )
        if html:
            logger.info("[EMAIL][CONSOLE-FALLBACK][HTML]\n%s", html)
        return {
            "ok": False,
            "accepted": True,
            "delivered": False,
            "mode": "console_fallback",
            "reason": "SMTP is not configured",
            "smtp_configured": False,
            "to": clean_to,
            "subject": clean_subject,
        }

    try:
        msg = EmailMessage()
        msg["From"] = smtp["email_from"]
        msg["To"] = clean_to
        msg["Subject"] = clean_subject
        msg.set_content(clean_body)

        if html:
            msg.add_alternative(html, subtype="html")

        # --------------------------------------------------------------------
        # Open the SMTP connection using either SSL or STARTTLS depending on
        # configuration.
        # --------------------------------------------------------------------
        if smtp["use_ssl"]:
            server = smtplib.SMTP_SSL(smtp["host"], smtp["port"], timeout=15)
        else:
            server = smtplib.SMTP(smtp["host"], smtp["port"], timeout=15)
            server.ehlo()
            if smtp["use_tls"]:
                server.starttls()
                server.ehlo()

        # Authenticate only when credentials exist.
        if smtp["user"] and smtp["password"]:
            server.login(smtp["user"], smtp["password"])

        server.send_message(msg)
        server.quit()

        logger.info("[EMAIL][SMTP] sent ok to=%s", clean_to)
        return {
            "ok": True,
            "accepted": True,
            "delivered": True,
            "mode": "smtp",
            "reason": "Delivered via SMTP",
            "smtp_configured": True,
            "to": clean_to,
            "subject": clean_subject,
        }

    except Exception as exc:
        logger.exception("[EMAIL][SMTP] send failed to=%s err=%s", clean_to, exc)
        return {
            "ok": False,
            "accepted": False,
            "delivered": False,
            "mode": "failed",
            "reason": str(exc),
            "smtp_configured": True,
            "to": clean_to,
            "subject": clean_subject,
        }


def send_email(to: str, subject: str, body: str, html: Optional[str] = None) -> bool:
    """
    Backward-compatible boolean wrapper.

    Historical behavior in this project treated console fallback as a truthy
    "accepted" send in development, so we preserve that behavior here.
    """
    result = send_email_result(to=to, subject=subject, body=body, html=html)
    return bool(result.get("accepted", False))


def send_email_template(*, to: str, template: str, context: Mapping[str, object]) -> bool:
    """
    Render a templated email and send it through the standard mail path.
    """
    subject, body = render_email_template(template, context)
    return send_email(to=to, subject=subject, body=body)