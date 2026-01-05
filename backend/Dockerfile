# ====================================================================
# backend/Dockerfile — Backend Container Image (Production-ready)
# --------------------------------------------------------------------
# FILE ROLE:
#   • Builds the Flask backend image used by docker-compose
#   • Installs system deps (psycopg2, build tools)
#   • Installs Python deps
#   • Runs Gunicorn for production
#
# NOTES:
#   • This Dockerfile assumes build context is ./backend
#   • requirements.txt must be inside ./backend
#   • Uploads stored at /app/uploads (mounted as a volume in compose)
# ====================================================================

FROM python:3.11-slim

# -----------------------------
# Python runtime safety
# -----------------------------
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1

WORKDIR /app

# -----------------------------
# System deps
# -----------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# Install Python deps
# -----------------------------
# Copy requirements first for better layer caching
COPY requirements.txt /tmp/requirements.txt

RUN pip install --upgrade pip \
 && pip install --no-cache-dir -r /tmp/requirements.txt

# -----------------------------
# Copy app source
# -----------------------------
COPY . .

# -----------------------------
# Uploads dir (served by Nginx from a shared volume)
# -----------------------------
RUN mkdir -p /app/uploads \
 && chmod -R 755 /app/uploads

ENV PYTHONPATH=/app

EXPOSE 5000

# -----------------------------
# Healthcheck (matches your /api/health)
# -----------------------------
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -fsS http://127.0.0.1:5000/api/health || exit 1

# -----------------------------
# Production command
# -----------------------------
# Uses your gunicorn config file if present.
# If you don't have gunicorn_config.py, either add it or replace the command.
CMD ["gunicorn", "-c", "gunicorn_config.py", "backend.wsgi:app"]
