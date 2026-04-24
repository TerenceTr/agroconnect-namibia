# ============================================================================
# backend/middleware/roles.py — Compatibility Shim
# ============================================================================
# FILE ROLE:
#   Legacy RBAC shim.
#
# CANONICAL LOCATION:
#   backend.security.require_admin / backend.security.require_farmer
# ============================================================================

from backend.security import require_admin, require_farmer

__all__ = ["require_admin", "require_farmer"]
