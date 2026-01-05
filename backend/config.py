# backend/config.py
# ====================================================================
# Central configuration for AgroConnect Backend (Flask)
# --------------------------------------------------------------------
# ROLE:
#   • Controls core application behavior
#   • Owns database connections and authentication secrets
#   • Authoritative source of business data
# ====================================================================

from __future__ import annotations
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ---------------- Security ----------------
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")
    JWT_SECRET = os.getenv("JWT_SECRET", "jwt-dev-secret")

    # ---------------- Database ----------------
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://postgres:postgres123@localhost:5432/agroconnect",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ---------------- CORS ----------------
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

    # ---------------- Token expiry (hours) ----------------
    ACCESS_TOKEN_HOURS = int(os.getenv("ACCESS_TOKEN_HOURS", "24"))
    VERIFICATION_EXP_HOURS = int(os.getenv("VERIFICATION_EXP_HOURS", "168"))
    RESET_EXP_HOURS = int(os.getenv("RESET_EXP_HOURS", "2"))

    # ---------------- Email (optional) ----------------
    MAIL_FROM = os.getenv("MAIL_FROM", "no-reply@agroconnect.local")
    MAIL_SERVER = os.getenv("MAIL_SERVER", "")
    MAIL_PORT = os.getenv("MAIL_PORT", "")
    MAIL_USERNAME = os.getenv("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.getenv("MAIL_PASSWORD", "")
    MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "false").lower() == "true"
    MAIL_USE_SSL = os.getenv("MAIL_USE_SSL", "false").lower() == "true"
