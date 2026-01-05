# ====================================================================
# backend/utils/__init__.py — Utilities Package Public API (Pyright-safe)
# --------------------------------------------------------------------
# FILE ROLE:
#   Defines the *public surface* of the backend.utils package.
#
# GOALS:
#   • Avoid circular imports during Flask startup
#   • Keep package import safe even if some utility modules are missing
#   • Keep Pyright/Pylance happy (static __all__ — no dynamic mutation)
#
# IMPORTANT NOTE ABOUT __all__:
#   Pyright expects __all__ to be static. If you build/append dynamically,
#   Pyright warns: "Operation on __all__ is not supported...".
#   So we export a stable list of "known-good" symbols only.
#
# USAGE:
#   Best practice (explicit imports; no reliance on __init__.py side-effects):
#     from backend.utils.upload_utils import save_image
#     from backend.utils.jwt_utils import jwt_encode
#
#   Optional convenience (works only if that module exists):
#     import backend.utils as utils
#     utils.upload_utils   # may exist
# ====================================================================

from __future__ import annotations

from importlib import import_module
from typing import Final, Optional

# --------------------------------------------------------------------
# Export list (STATIC).
# Only include submodules that you are sure exist in your repo.
# If any of these don't exist, you'll get an ImportError below — which is
# a *good* signal that your project structure is inconsistent.
# --------------------------------------------------------------------
__all__: Final[tuple[str, ...]] = (
    "upload_utils",
    "helpers",
    "jwt_utils",
    "sms",
    "validators",
)

# --------------------------------------------------------------------
# Lazy/optional imports for convenience:
#   - We DO NOT mutate __all__
#   - We avoid hard failures if some modules are temporarily missing
#   - The names appear on the package only when import succeeds
#
# If you want strict behavior, replace optional imports with normal imports.
# --------------------------------------------------------------------
def _optional_import(name: str) -> Optional[object]:
    """Import backend.utils.<name> if it exists, else return None."""
    try:
        return import_module(f"{__name__}.{name}")
    except ModuleNotFoundError:
        return None


# Bind optional modules to package attributes (no __all__ mutation).
upload_utils = _optional_import("upload_utils")
helpers = _optional_import("helpers")
jwt_utils = _optional_import("jwt_utils")
sms = _optional_import("sms")
validators = _optional_import("validators")
