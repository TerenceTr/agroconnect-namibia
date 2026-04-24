# ============================================================================
# backend/services/admin_audit_logger.py — Compatibility Shim
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Backward-compatible import shim.
#
# IMPORTANT:
#   Canonical implementation now lives in:
#     backend/services/audit_logger.py
#
# TODO:
#   Once all imports are updated to use:
#     from backend.services.audit_logger import log_admin_event
#   this file can be deleted.
# ============================================================================

from backend.services.audit_logger import log_admin_event

__all__ = ["log_admin_event"]