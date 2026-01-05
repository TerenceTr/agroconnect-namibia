# ============================================================================
# backend/routes/__init__.py — Blueprint Registry (Single Source of Truth)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Central place where all Flask Blueprints are registered.
#   backend/app.py calls register_blueprints(app) once at startup.
#
# KEY FIX:
#   Registering the SAME Blueprint twice needs a unique registration name:
#       app.register_blueprint(bp, url_prefix="/api/farmer", name="farmers_alias")
# ============================================================================

from __future__ import annotations

import importlib
import logging
from typing import Any, Optional, Protocol

from flask.blueprints import Blueprint

logger = logging.getLogger("backend.routes")


class BlueprintRegistrar(Protocol):
    """Anything that can register a Flask Blueprint (Flask app satisfies this)."""
    def register_blueprint(self, blueprint: Blueprint, **options: Any) -> None: ...


def _register(
    app: BlueprintRegistrar,
    module_path: str,
    blueprint_attr: str,
    url_prefix: str,
    *,
    required: bool = False,
    name_override: Optional[str] = None,
) -> None:
    """
    Import module, get Blueprint attribute, register with url_prefix.

    required=True:
      - missing blueprint/module raises (core endpoints must exist)

    name_override:
      - used to mount SAME blueprint object under a second prefix
      - fixes Flask 'already registered' warning
    """
    try:
        mod = importlib.import_module(module_path)
        bp = getattr(mod, blueprint_attr, None)

        if not isinstance(bp, Blueprint):
            raise RuntimeError(f"{module_path}.{blueprint_attr} is not a Flask Blueprint")

        options: dict[str, Any] = {"url_prefix": url_prefix}
        if name_override:
            options["name"] = name_override  # ✅ alias fix

        app.register_blueprint(bp, **options)
        logger.info("✅ Registered %s.%s at %s", module_path, blueprint_attr, url_prefix)

    except Exception as e:
        if required:
            raise
        logger.warning("⚠️ Skipped blueprint %s (%s): %s", module_path, url_prefix, e)


def register_blueprints(app: BlueprintRegistrar) -> None:
    """Register all application blueprints."""
    # ---------------- Core ----------------
    _register(app, "backend.routes.auth", "auth_bp", "/api/auth", required=True)
    _register(app, "backend.routes.products", "products_bp", "/api/products", required=True)
    _register(app, "backend.routes.cart", "cart_bp", "/api/cart", required=True)
    _register(app, "backend.routes.orders", "orders_bp", "/api/orders", required=True)
    _register(app, "backend.routes.users", "users_bp", "/api/users", required=True)
    _register(app, "backend.routes.farmers", "farmers_bp", "/api/farmers", required=True)

    # Alias (backward compatibility)
    _register(
        app,
        "backend.routes.farmers",
        "farmers_bp",
        "/api/farmer",
        required=False,
        name_override="farmers_alias",
    )

    # ---------------- Optional ----------------
    _register(app, "backend.routes.ratings", "ratings_bp", "/api/ratings", required=False)
    _register(app, "backend.routes.ai_analytics", "ai_bp", "/api/ai", required=False)

    # Admin modules
    _register(app, "backend.routes.admin_reports", "admin_reports_bp", "/api/admin/reports", required=False)
    _register(app, "backend.routes.admin_users", "admin_users_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_products", "admin_products_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_orders", "admin_orders_bp", "/api/admin/orders", required=False)
    _register(app, "backend.routes.admin_notifications", "admin_notifications_bp", "/api/admin/notifications", required=False)
    _register(app, "backend.routes.admin_audit_log", "admin_audit_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_settings", "admin_settings_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_analytics", "admin_analytics_bp", "/api/admin", required=False)
