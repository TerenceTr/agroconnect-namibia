# ====================================================================
# backend/__init__.py — Package Entry Point
# ====================================================================
# FILE ROLE:
#   • Makes `backend` a proper Python package
#   • Allows Flask CLI to locate the factory:
#       python -m flask --app backend:create_app run
#
# PYRIGHT NOTE:
#   Some type-checkers expect `models` to be an exported package attribute
#   if you write: `from backend import models`.
#   We expose it explicitly for IDE friendliness.
# ====================================================================

from __future__ import annotations

from backend.app import create_app

# Expose the models submodule as a package attribute (IDE/type-checker friendly)
import backend.models as models  # noqa: F401

__all__ = ["create_app", "models"]
