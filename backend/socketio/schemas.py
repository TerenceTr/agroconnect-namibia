# ====================================================================
# backend/socketio/schemas.py — Socket.IO Payload Schemas
# ====================================================================
# FILE ROLE:
#   • Typed schemas for Socket.IO event payloads
#   • Used for IDE support, linting, and validation hints
#
# IMPORTANT:
#   • No runtime dependency
#   • Safe to evolve without breaking clients
# ====================================================================

from __future__ import annotations

from typing import Literal, TypedDict


# --------------------------------------------------------------------
# Chat events
# --------------------------------------------------------------------
class ChatMessage(TypedDict):
    text: str
    timestamp: int


# --------------------------------------------------------------------
# Notification events
# --------------------------------------------------------------------
class NotificationPayload(TypedDict):
    type: Literal["order", "system", "info"]
    message: str


# --------------------------------------------------------------------
# Admin events
# --------------------------------------------------------------------
class AdminPing(TypedDict):
    nonce: str
