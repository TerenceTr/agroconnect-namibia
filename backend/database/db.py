# ====================================================================
# backend/database/db.py — DATABASE CORE (OPTION A, PROD-GRADE)
# ====================================================================
# FILE ROLE:
#   Single authoritative database layer for AgroConnect Namibia.
#
# WHAT THIS FILE OWNS:
#   • SQLAlchemy 2.x DeclarativeBase
#   • Flask-SQLAlchemy integration (db.Model)
#   • One global db instance (NO duplicates anywhere else)
#   • Safe engine access (fails fast when init_app is missing)
#   • Lazy model registration (prevents circular imports)
#
# OPTION A PHILOSOPHY:
#   • SQLAlchemy provides a runtime constructor for models
#   • Do NOT pass kwargs to model constructors (use assignments)
#   • Production uses Alembic migrations
#   • db.create_all() is DEV/TEST ONLY
#
# THIS FILE MUST NOT:
#   ❌ Import/create Flask app
#   ❌ Create SQLAlchemy engines manually
#   ❌ Contain business logic
# ====================================================================

from __future__ import annotations

from typing import Optional

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase


# ====================================================================
# DECLARATIVE BASE (SQLAlchemy 2.x)
# ====================================================================
class Base(DeclarativeBase):
    """
    Shared declarative base for all ORM models.

    All models inherit via:
        class User(db.Model):
            ...
    """
    pass


# ====================================================================
# GLOBAL SQLALCHEMY INSTANCE (SINGLETON)
# ====================================================================
db: SQLAlchemy = SQLAlchemy(model_class=Base)


# ====================================================================
# ENGINE ACCESS (SAFE / DEBUG-FRIENDLY)
# ====================================================================
def get_engine() -> Engine:
    """
    Return the active SQLAlchemy Engine.

    WHY:
      db.engine can be None if db.init_app(app) was never called.
      This helper fails fast with a clear message.

    Raises:
        RuntimeError: If the engine is not initialized.
    """
    engine: Optional[Engine] = getattr(db, "engine", None)

    if engine is None:
        raise RuntimeError(
            "SQLAlchemy engine not initialized. "
            "Did you forget db.init_app(app) inside create_app()?"
        )

    return engine


# ====================================================================
# LAZY MODEL REGISTRATION
# ====================================================================
def init_db(create_all: bool = False) -> None:
    """
    Import ORM models and optionally create tables.

    WHY LAZY IMPORTS:
      • Prevents circular imports (routes -> models -> db -> app issues)
      • Ensures db.Model is ready before model classes are evaluated

    Args:
        create_all (bool):
            False -> default (production-safe; use Alembic migrations)
            True  -> DEV/TEST ONLY (creates tables from metadata)
    """
    # ----------------------------------------------------------------
    # IMPORTANT:
    # Import ONLY models that exist in your project.
    # The imports are intentionally unused: importing registers tables.
    # ----------------------------------------------------------------
    try:
        # Core domain models
        from backend.models.user import User  # noqa: F401
        from backend.models.product import Product  # noqa: F401
        from backend.models.order import Order  # noqa: F401

        # Optional models (keep only if these files exist)
        try:
            from backend.models.rating import Rating  # noqa: F401
        except Exception:
            pass

        try:
            from backend.models.sms_log import SmsLog  # noqa: F401
        except Exception:
            pass

        try:
            from backend.models.market_trend import MarketTrend  # noqa: F401
        except Exception:
            pass

        # If you have Farmer model, enable this:
        # try:
        #     from backend.models.farmer import Farmer  # noqa: F401
        # except Exception:
        #     pass

    except ImportError as exc:
        raise RuntimeError(
            "Failed to import ORM models during init_db(). "
            "Check model paths, filenames, and that backend/ is a package "
            "(has __init__.py)."
        ) from exc

    # ----------------------------------------------------------------
    # TABLE CREATION (DEV / TEST ONLY)
    # ----------------------------------------------------------------
    if create_all:
        db.create_all()
