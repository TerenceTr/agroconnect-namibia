# ============================================================================
# backend/routes/__init__.py — Blueprint Registry (Single Source of Truth)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Central place where all Flask Blueprints are registered.
#   backend/app.py calls register_blueprints(app) once at startup.
#
# IMPORTANT CLEANUP / STABILITY IN THIS VERSION:
#   ✅ Keeps core marketplace blueprints registered from one place
#   ✅ Registers the lightweight public marketplace API for StartScreen
#   ✅ Registers review analytics and repeat-issue detection routes together
#   ✅ Keeps alias registrations explicit and editor-friendly
#   ✅ Keeps support modules OUT of the blueprint registry
#   ✅ Makes USSD registration fail-fast during development so Flask does not
#      silently skip the Africa's Talking endpoints
#
# WHY THE PUBLIC MARKETPLACE ROUTE WAS ADDED:
#   The StartScreen should not call multiple heavy product endpoints.
#   It should use one lightweight cached endpoint:
#
#       GET /api/public/marketplace-summary
#
#   This helps prevent:
#     • empty homepage product sections
#     • slow public marketplace loading
#     • frontend timeout errors
#     • duplicate API calls doing similar work
#
# WHY REPEAT ISSUE DETECTION IS REGISTERED HERE:
#   Farmer Quality Analytics uses both:
#
#       /api/reviews/analytics/...
#       /api/reviews/analytics/.../repeat-issues
#
#   If backend.routes.repeat_issue_detection is not registered, the page can
#   load the main analytics shell but still show:
#
#       "The requested URL was not found on the server."
#
#   Therefore repeat issue detection is mounted beside review analytics under
#   the same /api/reviews/analytics prefix.
# ============================================================================

from __future__ import annotations

import importlib
import logging
from typing import Any, Optional, Protocol

from flask.blueprints import Blueprint

logger = logging.getLogger("backend.routes")


# ----------------------------------------------------------------------------
# Protocol: anything that can register a Flask Blueprint
# ----------------------------------------------------------------------------
class BlueprintRegistrar(Protocol):
    """
    Minimal protocol satisfied by the Flask app object.

    We keep this protocol small so this registry stays easy to type-check.
    Flask's actual app object has many more methods, but this module only needs
    register_blueprint().
    """

    def register_blueprint(self, blueprint: Blueprint, **options: Any) -> None:
        ...


# ----------------------------------------------------------------------------
# Internal helper: safe dynamic import + register
# ----------------------------------------------------------------------------
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
    Import a module, resolve a Blueprint attribute, and register it.

    Parameters:
      app:
        Flask application object or any object that supports register_blueprint().

      module_path:
        Python import path for the route module.
        Example:
            "backend.routes.auth"

      blueprint_attr:
        Name of the Blueprint object inside that module.
        Example:
            "auth_bp"

      url_prefix:
        Prefix used when mounting the blueprint.
        Example:
            "/api/auth"

      required:
        True:
          - Any import failure, missing blueprint, or invalid blueprint raises.
          - Use for routes that the application must not run without.

        False:
          - Logs a warning and continues startup.
          - Use for optional modules so development remains resilient.

      name_override:
        Flask requires unique blueprint registration names.
        This option allows the same blueprint object to be mounted more than once
        for compatibility aliases.
    """
    try:
        mod = importlib.import_module(module_path)
        bp = getattr(mod, blueprint_attr, None)

        if not isinstance(bp, Blueprint):
            raise RuntimeError(f"{module_path}.{blueprint_attr} is not a Flask Blueprint")

        options: dict[str, Any] = {"url_prefix": url_prefix}

        # Required when mounting the same Blueprint object more than once.
        if name_override:
            options["name"] = name_override

        app.register_blueprint(bp, **options)
        logger.info("✅ Registered %s.%s at %s", module_path, blueprint_attr, url_prefix)

    except Exception as exc:
        if required:
            logger.exception("❌ Required blueprint failed: %s (%s)", module_path, url_prefix)
            raise

        logger.warning("⚠️ Skipped blueprint %s (%s): %s", module_path, url_prefix, exc)


# ----------------------------------------------------------------------------
# Public API: register every blueprint exactly once
# ----------------------------------------------------------------------------
def register_blueprints(app: BlueprintRegistrar) -> None:
    """
    Register all application blueprints.

    IMPORTANT:
      Keep this file as the single source of truth for route registration.

    RULES:
      1. Register route modules only.
      2. Do not register helper/service modules.
      3. Mount aliases explicitly with name_override.
      4. Use required=True only for routes the app must not run without.
    """

    # ------------------------------------------------------------------------
    # Core marketplace modules
    # ------------------------------------------------------------------------
    # These are required for the core application to function.
    # If one of these fails, startup should stop immediately.
    # ------------------------------------------------------------------------
    _register(app, "backend.routes.auth", "auth_bp", "/api/auth", required=True)
    _register(app, "backend.routes.products", "products_bp", "/api/products", required=True)

    # ------------------------------------------------------------------------
    # Public marketplace summary
    # ------------------------------------------------------------------------
    # Final endpoint:
    #   GET /api/public/marketplace-summary
    #
    # This is the lightweight public landing-page endpoint used by StartScreen.
    # ------------------------------------------------------------------------
    _register(
        app,
        "backend.routes.public_marketplace",
        "public_marketplace_bp",
        "/api/public",
        required=True,
    )

    _register(app, "backend.routes.cart", "cart_bp", "/api/cart", required=True)
    _register(app, "backend.routes.orders", "orders_bp", "/api/orders", required=True)
    _register(app, "backend.routes.users", "users_bp", "/api/users", required=True)
    _register(app, "backend.routes.farmers", "farmers_bp", "/api/farmers", required=True)

    # ------------------------------------------------------------------------
    # Backward-compatible farmer alias
    # ------------------------------------------------------------------------
    # Some frontend/service calls may still use /api/farmer.
    # Keep the alias until all callers are normalized to /api/farmers.
    # ------------------------------------------------------------------------
    _register(
        app,
        "backend.routes.farmers",
        "farmers_bp",
        "/api/farmer",
        required=False,
        name_override="farmers_alias",
    )

    # ------------------------------------------------------------------------
    # Farmer payment profile
    # ------------------------------------------------------------------------
    # Supports EFT / bank detail settings under both plural and singular prefixes:
    #   /api/farmers/...
    #   /api/farmer/...
    # ------------------------------------------------------------------------
    _register(
        app,
        "backend.routes.farmer_payment_profile",
        "farmer_payment_profile_bp",
        "/api/farmers",
        required=False,
    )
    _register(
        app,
        "backend.routes.farmer_payment_profile",
        "farmer_payment_profile_bp",
        "/api/farmer",
        required=False,
        name_override="farmer_payment_profile_alias",
    )

    # ------------------------------------------------------------------------
    # Farmer commerce settings
    # ------------------------------------------------------------------------
    # Supports merchant-specific seller controls under both plural and singular
    # prefixes.
    # ------------------------------------------------------------------------
    _register(
        app,
        "backend.routes.farmer_commerce_settings",
        "farmer_commerce_settings_bp",
        "/api/farmers",
        required=False,
    )
    _register(
        app,
        "backend.routes.farmer_commerce_settings",
        "farmer_commerce_settings_bp",
        "/api/farmer",
        required=False,
        name_override="farmer_commerce_settings_alias",
    )

    # ------------------------------------------------------------------------
    # Farmer / customer notifications
    # ------------------------------------------------------------------------
    # Mounted on both API-prefixed and compatibility alias routes.
    # ------------------------------------------------------------------------
    _register(
        app,
        "backend.routes.notifications",
        "notifications_bp",
        "/api/notifications",
        required=False,
    )
    _register(
        app,
        "backend.routes.notifications",
        "notifications_bp",
        "/notifications",
        required=False,
        name_override="notifications_alias",
    )

    # ------------------------------------------------------------------------
    # Customer likes
    # ------------------------------------------------------------------------
    # IMPORTANT:
    # likes.py already defines route fragments such as:
    #   /likes
    #   /product-likes
    #
    # Therefore the blueprint must be mounted ONCE at /api so final endpoints
    # become:
    #   /api/likes
    #   /api/product-likes
    #
    # Do NOT mount it at /api/likes or /api/product-likes, otherwise paths will
    # duplicate.
    # ------------------------------------------------------------------------
    _register(app, "backend.routes.likes", "likes_bp", "/api", required=False)

    # ------------------------------------------------------------------------
    # Presence / tracking
    # ------------------------------------------------------------------------
    _register(app, "backend.routes.presence", "presence_bp", "/api/presence", required=False)
    _register(
        app,
        "backend.routes.admin_presence",
        "admin_presence_bp",
        "/api/admin/presence",
        required=False,
    )
    _register(app, "backend.routes.events", "events_bp", "/api/events", required=False)

    # ------------------------------------------------------------------------
    # Customer commerce insights / workspace
    # ------------------------------------------------------------------------
    _register(
        app,
        "backend.routes.customer_insights",
        "customer_insights_bp",
        "/api/customer",
        required=False,
    )
    _register(
        app,
        "backend.routes.customer_insights",
        "customer_insights_bp",
        "/api/customers",
        required=False,
        name_override="customer_insights_alias",
    )

    _register(
        app,
        "backend.routes.customer_workspace",
        "customer_workspace_bp",
        "/api/customer",
        required=False,
    )
    _register(
        app,
        "backend.routes.customer_workspace",
        "customer_workspace_bp",
        "/api/customers",
        required=False,
        name_override="customer_workspace_alias",
    )

    # ------------------------------------------------------------------------
    # Review / ratings / analytics domain modules
    # ------------------------------------------------------------------------
    _register(app, "backend.routes.ratings", "ratings_bp", "/api/ratings", required=False)

    # Review quality routes:
    #   /api/reviews/...
    _register(
        app,
        "backend.routes.review_quality",
        "review_quality_bp",
        "/api/reviews",
        required=False,
    )

    # Review analytics routes:
    #   /api/reviews/analytics/...
    _register(
        app,
        "backend.routes.review_analytics",
        "review_analytics_bp",
        "/api/reviews/analytics",
        required=False,
    )

    # Repeat issue detection routes:
    #   /api/reviews/analytics/admin/repeat-issues
    #   /api/reviews/analytics/farmer/<farmer_id>/repeat-issues
    #
    # This is needed by Farmer Quality Analytics. Without this registration,
    # the page can show a red 404 message even when review_analytics is loaded.
    _register(
        app,
        "backend.routes.repeat_issue_detection",
        "repeat_issue_detection_bp",
        "/api/reviews/analytics",
        required=False,
    )

    # ------------------------------------------------------------------------
    # AI analytics / delivery
    # ------------------------------------------------------------------------
    _register(app, "backend.routes.ai_analytics", "ai_bp", "/api/ai", required=False)
    _register(app, "backend.routes.delivery", "delivery_bp", "/api/delivery", required=False)

    # ------------------------------------------------------------------------
    # Buyer / seller messaging
    # ------------------------------------------------------------------------
    _register(app, "backend.routes.messages", "messages_bp", "/api/messages", required=False)

    # ------------------------------------------------------------------------
    # USSD / Africa's Talking
    # ------------------------------------------------------------------------
    # IMPORTANT:
    # USSD is now a required integration for this build.
    #
    # We intentionally use required=True here so the app fails fast if:
    #   - backend.routes.ussd has an import error
    #   - ussd_bp is missing
    #   - a nested dependency inside the USSD stack fails at import time
    #
    # This is better than silently starting the server without:
    #   /api/ussd/africastalking
    #   /api/ussd/africastalking/events
    # ------------------------------------------------------------------------
    _register(app, "backend.routes.ussd", "ussd_bp", "/api/ussd", required=True)

    # ------------------------------------------------------------------------
    # Admin base / feature modules
    # ------------------------------------------------------------------------
    _register(app, "backend.routes.admin", "admin_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_users", "admin_users_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_products", "admin_products_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_orders", "admin_orders_bp", "/api/admin/orders", required=False)

    _register(
        app,
        "backend.routes.admin_notifications",
        "admin_notifications_bp",
        "/api/admin/notifications",
        required=False,
    )
    _register(app, "backend.routes.admin_audit_log", "admin_audit_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_settings", "admin_settings_bp", "/api/admin", required=False)
    _register(app, "backend.routes.admin_analytics", "admin_analytics_bp", "/api/admin", required=False)

    _register(
        app,
        "backend.routes.admin_reports",
        "admin_reports_bp",
        "/api/admin/reports",
        required=False,
    )

    _register(app, "backend.routes.admin_sla", "admin_sla_bp", "/api/admin", required=False)

    # ------------------------------------------------------------------------
    # IMPORTANT ARCHITECTURE NOTE
    # ------------------------------------------------------------------------
    # These are support modules, NOT Flask blueprints:
    #   backend/routes/orders_helpers.py
    #   backend/routes/orders_queries.py
    #   backend/routes/orders_serialization.py
    #
    # They must NEVER be registered here.
    #
    # Recommendation for later cleanup:
    #   - remove them if unused, OR
    #   - move them into backend/services/orders/
    #     during a later refactor.