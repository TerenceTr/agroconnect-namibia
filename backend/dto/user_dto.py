# =====================================================================
# backend/dto/user_dto.py
# ---------------------------------------------------------------------
# FILE ROLE:
#   Minimal, safe user representation.
#
# USED BY:
#   • Authentication responses
#   • Session payloads
#   • Audit logs
#
# SECURITY:
#   ❌ No passwords
#   ❌ No internal flags
# =====================================================================

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from uuid import UUID


@dataclass(frozen=True, slots=True)
class UserDTO:
    """
    Public-facing user identity.
    """

    id: UUID
    full_name: str
    role: int
    location: Optional[str]
