# ====================================================================
# backend/database/create_tables.py
# --------------------------------------------------------------------
# FILE ROLE:
#   Local development utility for creating database tables from models.
#
# PURPOSE:
#   • Bootstraps database schema from ORM models
#   • Used ONLY in local development or testing
#
# USAGE (from project root):
#   python -m backend.database.create_tables
#
# ⚠️ DO NOT USE IN PRODUCTION
#   Production environments MUST use Alembic migrations.
# ====================================================================

from __future__ import annotations

import sys
import inspect
from typing import Callable

from backend.config import Config
from backend.database import init_db


# ====================================================================
# APP FACTORY LOADER (SAFE + SIGNATURE-AWARE)
# ====================================================================
def _make_app():
    """
    Create a Flask app instance safely by inspecting the create_app()
    signature instead of guessing parameters.

    This avoids errors like:
      ❌ TypeError: got an unexpected keyword argument 'config_class'
    """

    try:
        from backend.app import create_app
    except Exception as exc:
        raise RuntimeError(
            "Could not import backend.app:create_app. "
            "Ensure backend/app.py exists and backend/ is a Python package."
        ) from exc

    if not callable(create_app):
        raise RuntimeError("create_app is not callable.")

    # ------------------------------------------------------------
    # Inspect create_app signature
    # ------------------------------------------------------------
    sig = inspect.signature(create_app)
    params = sig.parameters

    # ------------------------------------------------------------
    # CASE 1: create_app() -> no parameters
    # ------------------------------------------------------------
    if len(params) == 0:
        return create_app()

    # ------------------------------------------------------------
    # CASE 2: create_app(Config) or create_app(config)
    # ------------------------------------------------------------
    if len(params) == 1:
        return create_app(Config)

    # ------------------------------------------------------------
    # Anything else is unsupported
    # ------------------------------------------------------------
    raise RuntimeError(
        "Unsupported create_app signature detected. "
        f"Signature: {sig}\n"
        "Expected one of:\n"
        "  - create_app()\n"
        "  - create_app(Config)\n"
    )


# ====================================================================
# MAIN EXECUTION
# ====================================================================
def main() -> None:
    """
    Create all database tables from ORM models.

    Steps:
      1. Build Flask app
      2. Push application context
      3. Import/register models
      4. Run db.create_all()
    """
    app = _make_app()

    with app.app_context():
        init_db(create_all=True)
        print("✔ Database tables created successfully.")


# ====================================================================
# ENTRY POINT
# ====================================================================
if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("✖ Failed to create tables:")
        print(exc)
        sys.exit(1)
