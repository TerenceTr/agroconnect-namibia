# ============================================================================
# backend/__init__.py — Package Entry Point
# ============================================================================
# FILE ROLE:
#   • Makes `backend` a proper Python package
#   • Exposes create_app for Flask CLI imports
#
# IMPORTANT:
#   Avoid hard-importing optional models here.
#   Flask CLI imports the package before backend.app submodule is loaded.
# ============================================================================

from __future__ import annotations

from backend.app import create_app

# Optional: expose models for IDE convenience, but NEVER crash the package import.
try:
    import backend.models as models  # noqa: F401
except Exception:  # pragma: no cover
    models = None  # type: ignore

__all__ = ["create_app", "models"]
