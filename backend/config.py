# backend/config.py
# ============================================================================
# Central configuration for AgroConnect Backend (Flask)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   • Controls core application behavior
#   • Owns database connection + secrets
#   • Normalizes env values (booleans, comma-lists, ints, floats)
#   • Exposes feature flags used across routes/services
#
# KEY FIX IN THIS VERSION:
#   ✅ Explicitly loads backend/.env (and backend/.env.prod as fallback)
#      using paths relative to THIS file instead of relying on bare
#      load_dotenv(), which can miss backend/.env when Flask is started from
#      the project root.
#
# WHY THIS MATTERS FOR YOUR USSD ISSUE:
#   • Your pgAdmin screenshots show public.ussd_credentials exists and has rows
#   • But the running USSD app says the table is missing
#   • That strongly indicates the Flask app is reading a different DB URI
#   • This file fixes that by forcing the backend to load the intended env file
# ============================================================================

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

# ----------------------------------------------------------------------------
# Explicit env loading
# ----------------------------------------------------------------------------
# IMPORTANT:
#   We load env files relative to backend/config.py so the backend always reads
#   backend/.env even when Flask is launched from the REPO ROOT using:
#
#     python -m flask --app backend.app:create_app run --debug --port 5000
#
# Load order:
#   1) backend/.env.prod   (optional base/fallback)
#   2) backend/.env        (local developer override / preferred)
#
# override=True ensures the intended backend env wins over stale shell values.
_BACKEND_DIR = Path(__file__).resolve().parent
_ENV_PROD_PATH = _BACKEND_DIR / ".env.prod"
_ENV_PATH = _BACKEND_DIR / ".env"

if _ENV_PROD_PATH.exists():
    load_dotenv(_ENV_PROD_PATH, override=False)

if _ENV_PATH.exists():
    load_dotenv(_ENV_PATH, override=True)


# ----------------------------------------------------------------------------
# Env helpers (type-safe, tolerant)
# ----------------------------------------------------------------------------
def _as_bool(v: str | None, default: bool = False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in {"1", "true", "yes", "y", "on"}


def _as_int(v: str | None, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _as_float(v: str | None, default: float) -> float:
    try:
        return float(str(v).strip())
    except Exception:
        return default


def _as_csv_list(v: str | None) -> list[str]:
    raw = (v or "").strip()
    if not raw:
        return []
    return [x.strip() for x in raw.split(",") if x.strip()]


def _cors_origins(value: str) -> list[str] | str:
    """
    Accepts:
      - "*"  (allow all)
      - "http://a,http://b" (comma separated list)
    """
    raw = (value or "*").strip()
    if raw == "*":
        return "*"
    return [x.strip() for x in raw.split(",") if x.strip()]


def _is_sqlite(uri: str) -> bool:
    u = (uri or "").strip().lower()
    return u.startswith("sqlite:") or u.startswith("sqlite+pysqlite:")


class Config:
    # ---------------- Security ----------------
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    JWT_SECRET = os.getenv("JWT_SECRET", "jwt-dev-secret")

    # Optional service tokens (internal services / cron / AI microservice)
    # Used as: X-Service-Token: <token>
    BACKEND_SERVICE_TOKENS = set(_as_csv_list(os.getenv("BACKEND_SERVICE_TOKENS", "")))

    # ---------------- Runtime ----------------
    DEBUG = _as_bool(os.getenv("DEBUG"), False)
    FLASK_ENV = os.getenv("FLASK_ENV", "development")
    MAINTENANCE_MODE = _as_bool(os.getenv("MAINTENANCE_MODE"), False)

    # ---------------- Database ----------------
    # IMPORTANT:
    #   Because env files are now loaded explicitly above, DATABASE_URL should
    #   resolve from backend/.env in local development.
    #
    # Fallback remains in place as a defensive default only.
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:postgres123@localhost:5432/agroconnect",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # SQLAlchemy engine pool tuning (prevents QueuePool TimeoutError under load)
    # Defaults are safe for typical dev + small VPS deployments.
    DB_POOL_SIZE = _as_int(os.getenv("DB_POOL_SIZE"), 10)
    DB_MAX_OVERFLOW = _as_int(os.getenv("DB_MAX_OVERFLOW"), 20)
    DB_POOL_TIMEOUT = _as_int(os.getenv("DB_POOL_TIMEOUT"), 30)
    DB_POOL_RECYCLE = _as_int(os.getenv("DB_POOL_RECYCLE"), 1800)
    DB_POOL_PRE_PING = _as_bool(os.getenv("DB_POOL_PRE_PING"), True)

    # Useful while debugging SQL (off by default)
    SQLALCHEMY_ECHO = _as_bool(os.getenv("SQLALCHEMY_ECHO"), False)

    # IMPORTANT:
    #   Flask-SQLAlchemy reads SQLALCHEMY_ENGINE_OPTIONS automatically.
    if _is_sqlite(SQLALCHEMY_DATABASE_URI):
        SQLALCHEMY_ENGINE_OPTIONS = {"connect_args": {"check_same_thread": False}}
    else:
        SQLALCHEMY_ENGINE_OPTIONS = {
            "pool_pre_ping": DB_POOL_PRE_PING,
            "pool_size": DB_POOL_SIZE,
            "max_overflow": DB_MAX_OVERFLOW,
            "pool_timeout": DB_POOL_TIMEOUT,
            "pool_recycle": DB_POOL_RECYCLE,
        }

    # ---------------- CORS ----------------
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")
    CORS_ORIGINS_LIST = _cors_origins(CORS_ORIGINS)

    # ---------------- Token expiry (hours) ----------------
    ACCESS_TOKEN_HOURS = _as_int(os.getenv("ACCESS_TOKEN_HOURS"), 24)
    VERIFICATION_EXP_HOURS = _as_int(os.getenv("VERIFICATION_EXP_HOURS"), 168)
    RESET_EXP_HOURS = _as_int(os.getenv("RESET_EXP_HOURS"), 2)

    # ---------------- Hashing ----------------
    BCRYPT_LOG_ROUNDS = _as_int(os.getenv("BCRYPT_LOG_ROUNDS"), 12)

    # ---------------- Email (optional) ----------------
    # Support BOTH naming styles:
    #   - SMTP_*  (your templates)
    #   - MAIL_*  (older code)
    SMTP_HOST = os.getenv("SMTP_HOST") or os.getenv("MAIL_SERVER", "")
    SMTP_PORT = _as_int(os.getenv("SMTP_PORT") or os.getenv("MAIL_PORT"), 587)
    SMTP_USER = os.getenv("SMTP_USER") or os.getenv("MAIL_USERNAME", "")
    SMTP_PASS = os.getenv("SMTP_PASS") or os.getenv("MAIL_PASSWORD", "")
    SMTP_TLS = _as_bool(os.getenv("SMTP_TLS") or os.getenv("MAIL_USE_TLS"), True)
    SMTP_SSL = _as_bool(os.getenv("MAIL_USE_SSL"), False)
    EMAIL_FROM = os.getenv("EMAIL_FROM") or os.getenv("MAIL_FROM", "no-reply@agroconnect.local")

    # ---------------- SMS (optional) ----------------
    SMS_PROVIDER = os.getenv("SMS_PROVIDER", "console")
    SMS_SENDER = os.getenv("SMS_SENDER", "AgroConnect")

    # ---------------- Storage ----------------
    STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "local")
    STORAGE_BUCKET = os.getenv("STORAGE_BUCKET", "agroconnect")
    STORAGE_ENDPOINT = os.getenv("STORAGE_ENDPOINT", "http://localhost:9000")
    STORAGE_ACCESS_KEY = os.getenv("STORAGE_ACCESS_KEY", "minioadmin")
    STORAGE_SECRET_KEY = os.getenv("STORAGE_SECRET_KEY", "minioadmin")
    STORAGE_REGION = os.getenv("STORAGE_REGION", "us-east-1")

    # ---------------- AI / Research Controls ----------------
    ENABLE_AI_ENGINE = _as_bool(os.getenv("ENABLE_AI_ENGINE"), True)
    AI_ERROR_THRESHOLD = _as_int(os.getenv("AI_ERROR_THRESHOLD"), 5)
    AI_ERROR_WINDOW_SECONDS = _as_int(os.getenv("AI_ERROR_WINDOW_SECONDS"), 60)
    AI_DISABLE_SECONDS = _as_int(os.getenv("AI_DISABLE_SECONDS"), 120)

    # Stock alert scheduler toggle (best-effort background job runner)
    ENABLE_ASYNC_STOCK_ALERTS = _as_bool(os.getenv("ENABLE_ASYNC_STOCK_ALERTS"), True)

    # ---------------- Delivery / Distance Estimation ----------------
    ENABLE_DELIVERY_ESTIMATOR = _as_bool(os.getenv("ENABLE_DELIVERY_ESTIMATOR"), True)

    # Provider: "haversine" (offline estimate) or "google" (driving distance)
    DELIVERY_DISTANCE_PROVIDER = os.getenv("DELIVERY_DISTANCE_PROVIDER", "haversine").strip().lower()

    # If using google provider
    GOOGLE_MAPS_API_KEY = os.getenv("GOOGLE_MAPS_API_KEY", "").strip()

    # Fee model (N$)
    DELIVERY_BASE_FEE = _as_float(os.getenv("DELIVERY_BASE_FEE"), 25.0)
    DELIVERY_PER_KM = _as_float(os.getenv("DELIVERY_PER_KM"), 4.5)
    DELIVERY_FREE_KM = _as_float(os.getenv("DELIVERY_FREE_KM"), 0.0)
    DELIVERY_MIN_FEE = _as_float(os.getenv("DELIVERY_MIN_FEE"), 15.0)
    DELIVERY_MAX_FEE = _as_float(os.getenv("DELIVERY_MAX_FEE"), 200.0)

    # Caching for distance lookups (seconds)
    DELIVERY_DISTANCE_CACHE_TTL_SECONDS = _as_int(
        os.getenv("DELIVERY_DISTANCE_CACHE_TTL_SECONDS"), 86400
    )

    # ---------------- Logging ----------------
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()