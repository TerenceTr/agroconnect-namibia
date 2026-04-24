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
#   • Do NOT rely on kwargs in model constructors for strict typing
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
      db.engine can fail if db.init_app(app) was never called.
      This helper fails fast with a clear message.

    Raises:
        RuntimeError: If the engine is not initialized.
    """
    try:
        return db.engine
    except Exception as exc:
        raise RuntimeError(
            "SQLAlchemy engine not initialized. "
            "Did you forget db.init_app(app) inside create_app()?"
        ) from exc


# ====================================================================
# LAZY MODEL REGISTRATION
# ====================================================================
def init_db(create_all: bool = False) -> None:
    """
    Import ORM models and optionally create tables.

    WHY LAZY IMPORTS:
      • Prevent circular imports
      • Ensure db.Model is ready before model classes are evaluated

    Args:
        create_all (bool):
            False -> default (production-safe; use Alembic migrations)
            True  -> DEV/TEST ONLY (creates tables from metadata)
    """
    try:
        # ----------------------------------------------------------------
        # Core domain models
        # ----------------------------------------------------------------
        from backend.models.user import User  # noqa: F401
        from backend.models.product import Product  # noqa: F401
        from backend.models.order import Order  # noqa: F401
        from backend.models.order_item import OrderItem  # noqa: F401
        from backend.models.payment import Payment  # noqa: F401
        from backend.models.refresh_token import RefreshToken  # noqa: F401

        # ----------------------------------------------------------------
        # Admin / audit / moderation models
        # ----------------------------------------------------------------
        try:
            from backend.models.admin_audit_event import AdminAuditLog  # noqa: F401
        except Exception:
            pass

        try:
            from backend.models.product_like import ProductLike  # noqa: F401
        except Exception:
            pass

        # ----------------------------------------------------------------
        # Optional domain models
        # Keep only if these files exist in your project.
        # ----------------------------------------------------------------
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

        try:
            from backend.models.ai_stock_alert import AIStockAlert  # noqa: F401
        except Exception:
            pass

        try:
            from backend.models.login_event import LoginEvent  # noqa: F401
        except Exception:
            pass

        try:
            from backend.models.delivery_tier import DeliveryTier  # noqa: F401
        except Exception:
            pass

        try:
            from backend.models.farmer_delivery_tier import FarmerDeliveryTier  # noqa: F401
        except Exception:
            pass

        try:
            from backend.models.order_fulfillment import OrderFulfillment  # noqa: F401
        except Exception:
            pass

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