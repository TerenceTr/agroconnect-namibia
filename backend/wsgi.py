# ====================================================================
# backend/wsgi.py — Production WSGI Entrypoint
# --------------------------------------------------------------------
# Purpose:
#   • This file is the ONLY entrypoint used by WSGI servers in production.
#   • It exposes a Flask application object for:
#       - Gunicorn → "gunicorn backend.wsgi:app"
#       - Render’s auto-detected WSGI runner
#       - Docker deployments using Gunicorn
#
# IMPORTANT RULES:
#   • Do NOT run `socketio.run()` here.
#   • Do NOT import or start dev servers.
#   • This file must stay inside the backend/ folder so the module
#     path "backend.wsgi" remains valid.
# ====================================================================

from __future__ import annotations

# Import the application factory
from backend.app import create_app

# Create the actual Flask application instance
app = create_app()

# Some WSGI servers require the variable name "application"
# so we provide an alias for compatibility.
application = app
