# ====================================================================
# backend/routes/admin_settings.py — Admin System Settings (JWT)
# --------------------------------------------------------------------
# FILE ROLE:
#   Powers AdminSettingsPage.
#
# ROUTES:
#   GET  /api/admin/settings
#   POST /api/admin/settings     { cache_ttl: number, maintenance: boolean }
#   POST /api/admin/cache/flush
#
# PERSISTENCE:
#   Uses a tiny JSON file in backend/instance/ so it persists across restarts
#   without requiring a new DB table/migration.
# ====================================================================

from __future__ import annotations

import json
import os
from typing import Any, Optional

from flask.blueprints import Blueprint
from flask.globals import current_app, g, request
from flask.json import jsonify
from flask.wrappers import Response

from backend.models.user import ROLE_ADMIN, User
from backend.utils.require_auth import require_access_token

admin_settings_bp = Blueprint("admin_settings", __name__)


def _json(payload: Any, status: int = 200) -> Response:
    resp = jsonify(payload)
    resp.status_code = status
    return resp


def _current_user() -> Optional[User]:
    user = getattr(g, "current_user", None)
    if isinstance(user, User):
        return user
    user2 = getattr(request, "current_user", None)
    if isinstance(user2, User):
        return user2
    return None


def _admin_guard() -> Optional[Response]:
    user = _current_user()
    if user is None:
        return _json({"success": False, "message": "Authentication required"}, 401)
    if getattr(user, "role", None) != ROLE_ADMIN:
        return _json({"success": False, "message": "Admin access required"}, 403)
    return None


def _settings_path() -> str:
    inst = os.path.join(current_app.root_path, "instance")
    os.makedirs(inst, exist_ok=True)
    return os.path.join(inst, "admin_settings.json")


def _defaults() -> dict[str, Any]:
    return {
        "cache_ttl": int(current_app.config.get("CACHE_TTL", 300)),
        "maintenance": bool(current_app.config.get("MAINTENANCE_MODE", False)),
        "version": os.environ.get("APP_VERSION", "-"),
    }


def _read_settings() -> dict[str, Any]:
    path = _settings_path()
    if not os.path.exists(path):
        return _defaults()

    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
        base = _defaults()
        base.update({k: d.get(k, base[k]) for k in base.keys()})
        return base
    except Exception:
        return _defaults()


def _write_settings(d: dict[str, Any]) -> None:
    path = _settings_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=2)


@admin_settings_bp.route("/settings", methods=["GET"])
@require_access_token
def get_settings() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    d = _read_settings()

    # Sync into config for easy access elsewhere
    current_app.config["CACHE_TTL"] = int(d.get("cache_ttl", 300))
    current_app.config["MAINTENANCE_MODE"] = bool(d.get("maintenance", False))

    return _json(d, 200)


@admin_settings_bp.route("/settings", methods=["POST"])
@require_access_token
def save_settings() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    body = request.get_json(silent=True) or {}
    cache_ttl = body.get("cache_ttl", 300)
    maintenance = body.get("maintenance", False)

    try:
        cache_ttl = int(cache_ttl)
        if cache_ttl < 30:
            cache_ttl = 30
        if cache_ttl > 86400:
            cache_ttl = 86400
    except Exception:
        cache_ttl = 300

    maintenance = bool(maintenance)

    d = _read_settings()
    d["cache_ttl"] = cache_ttl
    d["maintenance"] = maintenance

    _write_settings(d)

    current_app.config["CACHE_TTL"] = cache_ttl
    current_app.config["MAINTENANCE_MODE"] = maintenance

    return _json({"success": True, "cache_ttl": cache_ttl, "maintenance": maintenance}, 200)


@admin_settings_bp.route("/cache/flush", methods=["POST"])
@require_access_token
def flush_cache() -> Response:
    guard = _admin_guard()
    if guard is not None:
        return guard

    # If you add a cache layer later, clear it here.
    return _json({"success": True, "message": "Cache flushed (no-op in dev)."}, 200)
