# ====================================================================
# backend/database/__init__.py
# --------------------------------------------------------------------
# FILE ROLE:
#   Public database interface for the backend package.
#
# WHAT THIS FILE DOES:
#   • Re-exports the single global SQLAlchemy instance (db)
#   • Re-exports Base + helpers (engine access, init_db)
#   • Keeps imports stable across the codebase:
#       from backend.database import db
#
# IMPORTANT RULE:
#   ❌ Do NOT import models here (avoids circular imports)
#   ✅ Models are imported ONLY inside init_db() in db.py
# ====================================================================

from __future__ import annotations

from .db import Base, db, get_engine, init_db

__all__ = ["db", "Base", "get_engine", "init_db"]
