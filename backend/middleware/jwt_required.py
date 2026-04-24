# ============================================================================
# backend/middleware/jwt_required.py — Compatibility Shim
# ============================================================================
# FILE ROLE:
#   Legacy import shim.
#
# CANONICAL LOCATION:
#   backend.security.jwt_required
# ============================================================================

from backend.security import jwt_required

__all__ = ["jwt_required"]
