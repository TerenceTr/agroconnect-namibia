"""
Custom management script for running the Flask application
and delegating to the Flask CLI for database migrations.

Usage:
    python manage.py run
    python manage.py db init
    python manage.py db migrate -m "Initial"
    python manage.py db upgrade
"""

import os
import sys

from app import create_app
from config import Config


# -----------------------------------------------------------
# Create Flask application (no type annotation to avoid IDE errors)
# -----------------------------------------------------------
app = create_app(Config)


def run_server():
    """
    Start the Flask development server.
    Works in local dev and Render deployment.
    """
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV") == "development"

    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug_mode
    )


def run_flask_cli():
    """
    Delegates to Flask CLI for commands like:
        python manage.py db migrate
        python manage.py db upgrade
    """
    try:
        from flask.cli import main as flask_cli
    except Exception as e:
        raise RuntimeError("Flask CLI could not be imported. Ensure Flask is installed.") from e

    flask_cli()


# -----------------------------------------------------------
# Main Entry
# -----------------------------------------------------------
if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"

    if cmd == "run":
        run_server()
    else:
        run_flask_cli()
