# ============================================================================
# backend/routes/ussd.py — Africa's Talking USSD Webhook Endpoints
# ----------------------------------------------------------------------------
# FILE ROLE:
#   • Exposes the public webhook endpoints used by Africa's Talking USSD
#   • Validates and logs inbound callback/event traffic
#   • Delegates all business/menu logic to backend/services/ussd_service.py
#
# ROUTES PROVIDED:
#   GET/POST /api/ussd/africastalking
#   GET/POST /api/ussd/africastalking/events
#
# IMPORTANT USSD RULE:
#   Africa's Talking expects a plain-text response body that begins with:
#     CON <message>   -> continue session
#     END <message>   -> end session
# Africa Talking USSD Code
# *384*33840#
#
# TYPE-CHECKING FIXES IN THIS VERSION:
#   ✅ Uses Flask submodule imports that are friendlier to Pylance/Pyright
#      in projects where `from flask import Blueprint, request` is flagged
#   ✅ Keeps all route handlers returning concrete Response objects
#   ✅ Avoids tuple returns like (jsonify(...), 200)
#   ✅ Avoids MultiDict.to_dict(flat=True) typing issues
# ============================================================================

from __future__ import annotations

import logging
from typing import Any

from flask.blueprints import Blueprint
from flask.globals import request
from flask.json import jsonify
from flask.wrappers import Response

from backend.services.ussd_service import (
    handle_ussd_event,
    process_ussd_callback,
    render_ussd_body,
)

# ---------------------------------------------------------------------------
# Blueprint registration
# ---------------------------------------------------------------------------
# Keep the blueprint creation simple and explicit so it remains compatible
# with common Flask/Pylance typing combinations used in this project.
ussd_bp = Blueprint("ussd", __name__)
logger = logging.getLogger("agroconnect.ussd.route")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _safe_str(value: Any, default: str = "") -> str:
    """Safely coerce any inbound value to a trimmed string."""
    if value is None:
        return default

    try:
        text_value = str(value).strip()
    except Exception:
        return default

    return text_value or default


def _plain_text(body: str, status_code: int = 200) -> Response:
    """
    Build a plain-text Flask response.

    Africa's Talking expects a body that starts with CON or END.
    """
    response = Response(body, mimetype="text/plain")
    response.status_code = status_code
    return response


def _json_response(payload: dict[str, Any], status_code: int = 200) -> Response:
    """
    Build a JSON Flask response without returning a tuple.

    Returning a concrete Response keeps Flask decorators and static type
    checkers aligned.
    """
    response = jsonify(payload)
    response.status_code = status_code
    return response


def _request_payload_dict() -> dict[str, str]:
    """
    Convert request form/query values into a plain dict[str, str].

    We intentionally avoid MultiDict.to_dict(flat=True) because some typing
    stubs mark that signature too narrowly and trigger false-positive errors.
    """
    source = request.form if request.form else request.values
    payload: dict[str, str] = {}

    for key in source.keys():
        payload[key] = _safe_str(source.get(key))

    return payload


# ---------------------------------------------------------------------------
# Africa's Talking main callback
# ---------------------------------------------------------------------------
@ussd_bp.route("/africastalking", methods=["GET", "POST"])
def africastalking_callback() -> Response:
    """
    Main Africa's Talking USSD callback endpoint.

    Expected request fields:
      • sessionId
      • serviceCode
      • phoneNumber
      • text
    """
    if request.method == "GET":
        return _json_response(
            {
                "ok": True,
                "message": "AgroConnect Africa's Talking USSD callback is online.",
            }
        )

    form = request.form if request.form else request.values

    session_id = _safe_str(form.get("sessionId"))
    service_code = _safe_str(form.get("serviceCode"))
    phone_number = _safe_str(form.get("phoneNumber"))
    text_value = _safe_str(form.get("text"))

    logger.info(
        "[USSD ROUTE][CALLBACK] session=%s serviceCode=%s phone=%s text=%s",
        session_id,
        service_code,
        phone_number,
        text_value,
    )

    if not session_id:
        return _plain_text("END Missing sessionId")

    if not phone_number:
        return _plain_text("END Missing phoneNumber")

    try:
        response_model = process_ussd_callback(
            session_id=session_id,
            service_code=service_code,
            phone_number=phone_number,
            text_value=text_value,
        )
        return _plain_text(render_ussd_body(response_model))

    except Exception as exc:
        logger.exception("[USSD ROUTE][CALLBACK] Processing failed: %s", exc)
        return _plain_text("END We could not process your request. Please try again.")


# ---------------------------------------------------------------------------
# Africa's Talking end-of-session events
# ---------------------------------------------------------------------------
@ussd_bp.route("/africastalking/events", methods=["GET", "POST"])
def africastalking_events() -> Response:
    """
    End-of-session / event callback endpoint.

    This endpoint is intentionally lightweight:
      • GET confirms the route is online
      • POST logs the inbound event payload
      • business-side handling is delegated to the USSD service layer
    """
    if request.method == "GET":
        return _json_response(
            {
                "ok": True,
                "message": "AgroConnect Africa's Talking USSD events endpoint is online.",
            }
        )

    payload = _request_payload_dict()
    logger.info("[USSD ROUTE][EVENT] payload=%s", payload)

    try:
        handle_ussd_event(payload)
    except Exception as exc:
        logger.exception("[USSD ROUTE][EVENT] Event handling failed: %s", exc)
        return _json_response(
            {
                "ok": False,
                "message": "USSD event received but handling failed internally.",
            }
        )

    return _json_response({"ok": True, "message": "USSD event received"})