# ====================================================================
# Gunicorn Configuration for AgroConnect Backend
# --------------------------------------------------------------------
# Why this file is required:
#   • Flask-SocketIO requires eventlet (or gevent) for WebSocket support.
#   • Gunicorn uses a WSGI entrypoint (backend.wsgi:app) instead of
#     the development server.
#   • Render, Docker, and production deployments all use this file.
#
# Notes:
#   • Bind port MUST match the container service port (5000).
#   • Worker class MUST be "eventlet" for Socket.IO.
#   • Starter plans on Render only allow 1 worker.
# ====================================================================

# Listen on all IP addresses inside the container
bind = "0.0.0.0:5000"

# Required for Flask-SocketIO real-time support
worker_class = "eventlet"

# Compatible with Render starter plan (1 CPU)
workers = 1

# Extended timeout — useful for image uploads & heavy DB operations
timeout = 120

# Cleaner logging for production debugging
loglevel = "info"
