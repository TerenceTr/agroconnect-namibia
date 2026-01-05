# ============================================================================
# backend/app.py — AgroConnect Namibia (APPLICATION FACTORY)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Main Flask entrypoint using the Application Factory pattern.
#   Single source of truth for creating/configuring the Flask app.
#
# RESPONSIBILITIES:
#   • Build Flask app (config + extensions)
#   • Configure CORS (for /api/*)
#   • Initialize extensions: SQLAlchemy, Migrations, Bcrypt, Socket.IO
#   • Import ORM models early (prevents mapper errors)
#   • Register ALL REST blueprints under /api/*
#   • Provide health + uploads endpoints
#   • Enforce JSON-only error handling
#
# KEY FIX:
#   Pyright/Pylance may flag "from backend import models" as unknown because
#   `models` isn't exported from backend/__init__.py.
#   ✅ Solution: import the submodule directly: `import backend.models as _models`.
# ============================================================================

from __future__ import annotations

import logging
import os
from typing import Any, Optional, Type, cast

from flask import send_from_directory
from flask.app import Flask
from flask.json import jsonify
from flask.globals import current_app, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from backend.config import Config
from backend.database.db import db
from backend.extensions import bcrypt, init_socketio, migrate, socketio

logger = logging.getLogger("agroconnect.app")
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO").upper())


def _parse_csv_env(name: str) -> list[str]:
    """Read a comma-separated env var into a clean list of values."""
    raw = os.environ.get(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]


def _ensure_upload_dirs(root: str) -> dict[str, str]:
    """
    Ensure uploads structure exists:

      <app.root_path>/uploads/
        defaults/
        public_images/

    Returns:
      Dict with resolved directories used by upload routes.
    """
    os.makedirs(root, exist_ok=True)

    defaults_dir = os.path.join(root, "defaults")
    public_images_dir = os.path.join(root, "public_images")
    os.makedirs(defaults_dir, exist_ok=True)
    os.makedirs(public_images_dir, exist_ok=True)

    return {
        "upload_root": root,
        "defaults_dir": defaults_dir,
        "public_images_dir": public_images_dir,
    }


def create_app(config_object: Optional[Type[Config]] = None) -> Flask:
    """
    Build and configure the Flask app instance.

    Notes:
      • Import this from WSGI/ASGI runners and CLI scripts.
      • Do NOT start the server here (that's handled under __main__).
    """
    app = Flask(__name__, static_folder=None)

    # ----------------------------
    # Config
    # ----------------------------
    cfg = config_object or Config
    app.config.from_object(cfg)

    # ----------------------------
    # CORS (only /api/*)
    # ----------------------------
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    cors_origins.extend(_parse_csv_env("CORS_ORIGINS"))

    CORS(
        app,
        resources={r"/api/*": {"origins": cors_origins}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Service-Token"],
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        max_age=86400,
    )

    # ----------------------------
    # Extensions
    # ----------------------------
    db.init_app(cast(Any, app))
    migrate.init_app(cast(Any, app), db)
    bcrypt.init_app(cast(Any, app))

    # ----------------------------
    # Import models early (mapper stability)
    # ----------------------------
    # ✅ Pyright-friendly: import submodule directly
    try:
        import backend.models as _models  # noqa: F401
    except Exception as exc:
        logger.warning("⚠️ Could not import backend.models (check model imports): %s", exc)

    # ----------------------------
    # Socket.IO (optional realtime)
    # ----------------------------
    # ✅ init_socketio() only uses Redis if REDIS_URL is set AND reachable.
    init_socketio(app, cors_allowed_origins=cors_origins)

    @socketio.on("presence:join")
    def presence_join(payload: Any) -> None:
        """Optional presence event (keep minimal)."""
        _ = payload
        return

    # ----------------------------
    # Upload directories
    # ----------------------------
    upload_paths = _ensure_upload_dirs(os.path.join(app.root_path, "uploads"))
    upload_root = upload_paths["upload_root"]
    public_images_dir = upload_paths["public_images_dir"]

    # ----------------------------
    # Blueprints (API routes)
    # ----------------------------
    from backend.routes import register_blueprints

    register_blueprints(app)
    logger.info("✅ API routes registered")

    # ----------------------------
    # Maintenance mode gate (optional)
    # ----------------------------
    @cast(Any, app).before_request
    def maintenance_gate():  # type: ignore[no-untyped-def]
        """
        If MAINTENANCE_MODE=True, block /api calls (except /api/health).
        """
        if not current_app.config.get("MAINTENANCE_MODE", False):
            return None

        if not request.path.startswith("/api"):
            return None

        if request.path == "/api/health":
            return None

        resp = jsonify({"success": False, "message": "Service temporarily in maintenance mode."})
        resp.status_code = 503
        return resp

    # ----------------------------
    # Health endpoint
    # ----------------------------
    @cast(Any, app).get("/api/health")
    def health() -> Any:
        """Simple health check used by deployments and local testing."""
        return jsonify({"status": "ok", "service": "AgroConnect API"})

    # ----------------------------
    # Static uploads
    # ----------------------------
    @cast(Any, app).get("/api/uploads/<path:folder>/<path:filename>")
    def serve_upload(folder: str, filename: str) -> Any:
        """Serve uploaded files from uploads/<folder>/<filename>."""
        target_dir = os.path.join(upload_root, folder)
        if not os.path.isdir(target_dir):
            resp = jsonify({"success": False, "message": "Upload folder not found"})
            resp.status_code = 404
            return resp
        return send_from_directory(target_dir, filename)

    @cast(Any, app).get("/api/uploads/public_images/<path:filename>")
    def serve_public_image(filename: str) -> Any:
        """Convenience endpoint used by product images."""
        return send_from_directory(public_images_dir, filename)

    # ----------------------------
    # Security-ish headers
    # ----------------------------
    @cast(Any, app).after_request
    def add_common_headers(response):  # type: ignore[no-untyped-def]
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        return response

    # ----------------------------
    # Global JSON-only error handler
    # ----------------------------
    @cast(Any, app).errorhandler(Exception)
    def handle_error(error: Exception) -> Any:
        """Enforce JSON errors for HTTP errors and unexpected crashes."""
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
    app = create_app()
    socketio.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=os.environ.get("FLASK_ENV") == "development",
    )
