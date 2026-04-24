# ============================================================================
# backend/middleware/service_auth.py — Compatibility Shim
# ============================================================================
# FILE ROLE:
#   Legacy import shim.
#
# CANONICAL LOCATION:
#   backend.security.service_token_required
# ============================================================================

from backend.security import service_token_required

__all__ = ["service_token_required"]
