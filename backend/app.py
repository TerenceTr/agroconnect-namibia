# ============================================================================
# backend/app.py — AgroConnect Namibia (APPLICATION FACTORY)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Main Flask entrypoint using the Application Factory pattern.
#
# RESPONSIBILITIES:
#   • Build Flask app (config + extensions)
#   • Apply persisted system settings into app.config at startup
#   • Configure CORS for /api/*
#   • Initialize extensions: SQLAlchemy, Migrations, Bcrypt, Socket.IO
#   • Import ORM models early (prevents mapper errors) + FAIL FAST
#   • Register all REST blueprints under /api/*
#   • Provide health + uploads endpoints
#   • Enforce JSON-only API error handling
#
# KEY FIXES IN THIS VERSION:
#   ✅ Removes send_file import entirely
#   ✅ Uses send_from_directory only (better Pylance compatibility)
#   ✅ Keeps request import from canonical Flask module
#   ✅ Keeps Flask type consistency for apply_system_settings_to_app(...)
#   ✅ Keeps upload/default-image compatibility improvements
# ============================================================================

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable, MutableMapping
from typing import Any, Optional, Type, cast

from flask.app import Flask
from flask.globals import request
from flask.helpers import send_from_directory
from flask.json import jsonify
from flask.wrappers import Response
from flask_cors import CORS
from sqlalchemy.orm import configure_mappers
from werkzeug.exceptions import HTTPException

from backend.config import Config
from backend.database.db import db
from backend.extensions import bcrypt, init_socketio, migrate, socketio
from backend.services.system_settings import apply_system_settings_to_app

logger = logging.getLogger("agroconnect.app")


# -----------------------------------------------------------------------------
# Frontend asset discovery helpers
# -----------------------------------------------------------------------------
def _candidate_frontend_assets_dirs() -> list[str]:
    """
    Resolve likely frontend Assets folders for both development and production.
    """
    here = os.path.dirname(__file__)
    candidates = [
        os.path.abspath(os.path.join(here, "..", "..", "frontend", "public", "Assets")),
        os.path.abspath(os.path.join(here, "..", "..", "frontend", "build", "Assets")),
        os.path.abspath(os.path.join(here, "..", "frontend", "public", "Assets")),
        os.path.abspath(os.path.join(here, "..", "frontend", "build", "Assets")),
    ]

    out: list[str] = []
    for path in candidates:
        if path not in out and os.path.isdir(path):
            out.append(path)
    return out


def _send_existing_file(path: str) -> Any:
    """
    Serve an already-verified file path using send_from_directory.

    WHY THIS EXISTS:
      We intentionally avoid send_file(...) here because some static analyzers
      report it as an unknown import symbol in certain Flask stub environments.
      Splitting the absolute path into directory + filename lets us keep the
      same runtime behavior without importing send_file at all.
    """
    directory = os.path.dirname(path)
    filename = os.path.basename(path)
    return send_from_directory(directory, filename)


def _send_default_product_image() -> Any:
    """
    Return the best available default product image.

    Priority:
      1. Backend upload default
      2. Frontend bundled asset fallback(s)
    """
    candidates = [
        os.path.join(os.path.dirname(__file__), "uploads", "product_images", "default.png"),
        os.path.join(os.path.dirname(__file__), "uploads", "product_images", "default.jpg"),
    ]

    for assets_dir in _candidate_frontend_assets_dirs():
        candidates.extend(
            [
                os.path.join(assets_dir, "product_images", "default.jpg"),
                os.path.join(assets_dir, "product_images", "default.png"),
                os.path.join(assets_dir, "default-product.jpg"),
                os.path.join(assets_dir, "default.jpg"),
                os.path.join(assets_dir, "default.png"),
            ]
        )

    for path in candidates:
        if os.path.isfile(path):
            return _send_existing_file(path)

    resp = jsonify({"success": False, "message": "Default image not found"})
    resp.status_code = 404
    return resp


StartResponse = Callable[..., Any]
WSGIApp = Callable[[MutableMapping[str, Any], StartResponse], Any]


# -----------------------------------------------------------------------------
# Small setup helpers
# -----------------------------------------------------------------------------
def _ensure_upload_dirs(root: str) -> dict[str, str]:
    """
    Ensure the upload directory tree exists.

    Returns commonly used directory paths for route setup.
    """
    os.makedirs(root, exist_ok=True)

    defaults_dir = os.path.join(root, "defaults")
    public_images_dir = os.path.join(root, "public_images")
    payment_proofs_dir = os.path.join(root, "payment_proofs")
    product_images_dir = os.path.join(root, "product_images")

    os.makedirs(defaults_dir, exist_ok=True)
    os.makedirs(public_images_dir, exist_ok=True)
    os.makedirs(payment_proofs_dir, exist_ok=True)
    os.makedirs(product_images_dir, exist_ok=True)

    return {
        "upload_root": root,
        "defaults_dir": defaults_dir,
        "public_images_dir": public_images_dir,
        "payment_proofs_dir": payment_proofs_dir,
        "product_images_dir": product_images_dir,
    }


def _options_preflight_response() -> Response:
    """Return a 204 response for browser CORS preflight."""
    return Response(status=204)


def _build_cors_origins(app: Flask) -> Any:
    """
    Build the effective CORS origin configuration.

    Keeps local development friendly while allowing config-driven overrides.
    """
    cfg_val = app.config.get("CORS_ORIGINS_LIST", "*")

    cors_origins: list[Any] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        re.compile(r"^http://192\.168\.\d+\.\d+:3000$"),
        re.compile(r"^http://10\.\d+\.\d+\.\d+:3000$"),
    ]

    if cfg_val == "*":
        cors_origins.append(re.compile(r"^https?://.+$"))
        return cors_origins

    if isinstance(cfg_val, list):
        cors_origins.extend(cfg_val)
        return cors_origins

    cors_origins.append(re.compile(r"^https?://.+$"))
    return cors_origins


def _configure_logging_from_env() -> None:
    """Initialize root logging level from LOG_LEVEL."""
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level)


def _wrap_wsgi_collapse_double_api_prefix(wsgi_app: WSGIApp) -> WSGIApp:
    """
    Defensive middleware that collapses accidental /api/api/... requests.
    """

    def _middleware(
        environ: MutableMapping[str, Any],
        start_response: StartResponse,
    ) -> Any:
        path = str(environ.get("PATH_INFO") or "")

        if path.startswith("/api/api/"):
            environ["PATH_INFO"] = "/api/" + path[len("/api/api/") :]
        elif path == "/api/api":
            environ["PATH_INFO"] = "/api"

        return wsgi_app(environ, start_response)

    return _middleware


# -----------------------------------------------------------------------------
# Application factory
# -----------------------------------------------------------------------------
def create_app(config_object: Optional[Type[Config]] = None) -> Flask:
    """
    Build and return the Flask application instance.
    """
    _configure_logging_from_env()

    app = Flask(__name__, static_folder=None)
    app_any = cast(Any, app)

    # -------------------------------------------------------------------------
    # WSGI middleware
    # -------------------------------------------------------------------------
    current_wsgi = cast(WSGIApp, getattr(app_any, "wsgi_app"))
    setattr(app_any, "wsgi_app", _wrap_wsgi_collapse_double_api_prefix(current_wsgi))

    # -------------------------------------------------------------------------
    # Base config + persisted system settings
    # -------------------------------------------------------------------------
    cfg = config_object or Config
    app.config.from_object(cfg)

    # NOTE:
    # Pass the concrete flask.app.Flask instance.
    resolved_settings = apply_system_settings_to_app(app)

    logger.info(
        "✅ System settings applied (maintenance=%s, read_only=%s, cache_ttl=%s, version=%s)",
        bool(app.config.get("MAINTENANCE_MODE", False)),
        bool(app.config.get("READ_ONLY_MODE", False)),
        int(app.config.get("CACHE_TTL", 300)),
        str(app.config.get("APP_VERSION", "-")),
    )

    # -------------------------------------------------------------------------
    # CORS
    # -------------------------------------------------------------------------
    cors_origins = _build_cors_origins(app)
    CORS(
        app_any,
        resources={r"/api/*": {"origins": cors_origins}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Service-Token"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
    )

    # -------------------------------------------------------------------------
    # Extensions
    # -------------------------------------------------------------------------
    db.init_app(app_any)
    migrate.init_app(app_any, db)
    bcrypt.init_app(app_any)

    # -------------------------------------------------------------------------
    # Preflight handling only
    # -------------------------------------------------------------------------
    @app_any.before_request
    def handle_preflight() -> Any:
        """
        Always allow browser preflight requests.

        Maintenance mode is advisory only and does not block usage.
        """
        if request.method == "OPTIONS":
            return _options_preflight_response()
        return None

    # -------------------------------------------------------------------------
    # DB session hygiene
    # -------------------------------------------------------------------------
    @app_any.before_request
    def _ensure_clean_db_session() -> None:
        """
        Prevent reuse of a failed SQLAlchemy transaction across requests.
        """
        if request.method == "OPTIONS":
            return

        try:
            if (
                hasattr(db, "session")
                and hasattr(db.session, "is_active")
                and not db.session.is_active
            ):
                db.session.rollback()
        except Exception:
            pass

    @app_any.teardown_request
    def _cleanup_db_session(exception: Optional[BaseException] = None) -> None:
        """
        Ensure every request leaves the scoped session in a clean state.
        """
        try:
            if exception is not None:
                db.session.rollback()
        except Exception:
            pass
        finally:
            try:
                db.session.remove()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # ORM import + mapper configuration
    # -------------------------------------------------------------------------
    try:
        import backend.models as _models  # noqa: F401

        configure_mappers()
        logger.info("✅ ORM models imported and mappers configured")
    except Exception:
        logger.exception("❌ ORM model import / mapper configuration failed")
        raise

    # -------------------------------------------------------------------------
    # Socket.IO
    # -------------------------------------------------------------------------
    init_socketio(app_any, cors_allowed_origins=cors_origins)

    try:
        from backend.socketio.namespaces import register_namespaces

        register_namespaces(socketio)
        logger.info("✅ Socket.IO namespaces registered")
    except Exception:
        logger.exception("❌ Socket.IO namespace registration failed")
        raise

    @socketio.on("presence:join")
    def presence_join(payload: Any) -> None:
        _ = payload
        return None

    # -------------------------------------------------------------------------
    # Upload paths
    # -------------------------------------------------------------------------
    upload_paths = _ensure_upload_dirs(os.path.join(app.root_path, "uploads"))
    upload_root = upload_paths["upload_root"]
    public_images_dir = upload_paths["public_images_dir"]

    app.config["UPLOAD_FOLDER"] = upload_root
    app.config.setdefault(
        "MAX_PAYMENT_PROOF_MB",
        int(resolved_settings.get("payments", {}).get("max_payment_proof_mb", 5)),
    )

    # -------------------------------------------------------------------------
    # Blueprints
    # -------------------------------------------------------------------------
    from backend.routes import register_blueprints

    register_blueprints(app_any)
    logger.info("✅ API routes registered")

    # -------------------------------------------------------------------------
    # Lightweight utility routes
    # -------------------------------------------------------------------------
    @app_any.get("/api/health")
    def health() -> Any:
        """
        Operational health endpoint used by the frontend/admin UI.
        """
        return jsonify(
            {
                "status": "ok",
                "service": "AgroConnect API",
                "version": str(app.config.get("APP_VERSION", "-")),
                "maintenance": bool(app.config.get("MAINTENANCE_MODE", False)),
                "read_only_mode": bool(app.config.get("READ_ONLY_MODE", False)),
            }
        )

    @app_any.get("/api/uploads/<path:folder>/<path:filename>")
    def serve_upload(folder: str, filename: str) -> Any:
        """
        Serve uploaded files. If an old default-image path is requested,
        return the canonical default image instead of repeated 404 noise.
        """
        target_dir = os.path.join(upload_root, folder)
        candidate = os.path.join(target_dir, filename)

        if os.path.isdir(target_dir) and os.path.isfile(candidate):
            return send_from_directory(target_dir, filename)

        if folder.lower() in {"defaults", "default", "product_images"}:
            return _send_default_product_image()

        resp = jsonify({"success": False, "message": "Upload file not found"})
        resp.status_code = 404
        return resp

    @app_any.get("/api/uploads/public_images/<path:filename>")
    def serve_public_image(filename: str) -> Any:
        """
        Serve public image assets from uploads/public_images.
        """
        return send_from_directory(public_images_dir, filename)

    @app_any.get("/uploads/<path:folder>/<path:filename>")
    def serve_upload_compat(folder: str, filename: str) -> Any:
        """
        Backward-compatible alias for older /uploads/... style URLs.
        """
        return serve_upload(folder, filename)

    @app_any.get("/Assets/<path:filename>")
    @app_any.get("/assets/<path:filename>")
    def serve_frontend_asset(filename: str) -> Any:
        """
        Serve frontend asset files when the browser requests bundled assets.
        """
        for assets_dir in _candidate_frontend_assets_dirs():
            candidate = os.path.join(assets_dir, filename)
            if os.path.isfile(candidate):
                return send_from_directory(assets_dir, filename)

        normalized = filename.lower().replace("\\", "/")
        if normalized in {
            "default.jpg",
            "default.png",
            "default-product.jpg",
            "product_images/default.jpg",
            "product_images/default.png",
        }:
            return _send_default_product_image()

        resp = jsonify({"success": False, "message": "Asset not found"})
        resp.status_code = 404
        return resp

    # -------------------------------------------------------------------------
    # Common headers
    # -------------------------------------------------------------------------
    @app_any.after_request
    def add_common_headers(response: Any) -> Any:
        """
        Add security + operational status headers.
        """
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")

        response.headers["X-AgroConnect-Maintenance"] = (
            "true" if bool(app.config.get("MAINTENANCE_MODE", False)) else "false"
        )
        response.headers["X-AgroConnect-Read-Only"] = (
            "true" if bool(app.config.get("READ_ONLY_MODE", False)) else "false"
        )

        return response

    # -------------------------------------------------------------------------
    # Global JSON error handler
    # -------------------------------------------------------------------------
    @app_any.errorhandler(Exception)
    def handle_error(error: Exception) -> Any:
        """
        Global API-safe error handler.
        """
        try:
            db.session.rollback()
        except Exception:
            pass

        if isinstance(error, HTTPException):
            resp = jsonify({"success": False, "message": error.description})
            resp.status_code = error.code or 500
            return resp

        logger.exception("Unhandled server error")
        resp = jsonify({"success": False, "message": "Internal server error"})
        resp.status_code = 500
        return resp

    return app


if __name__ == "__main__":
    _app = create_app()
    socketio.run(
        _app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_ENV") == "development",
    )