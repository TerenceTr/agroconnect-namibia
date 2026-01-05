#!/usr/bin/env bash
set -euo pipefail

# backend/entrypoint.sh
# Wait-for-db + optional migrations then exec CMD (gunicorn)
# The script uses environment variables:
#  - DATABASE_URL (used by Flask-SQLAlchemy)
#  - RUN_MIGRATIONS=true|false

# Simple wait-for-postgres
host_from_url() {
  python - <<'PY'
import os, sys, urllib.parse as u
db = os.environ.get("DATABASE_URL", "")
if db:
    parsed = u.urlparse(db)
    print(parsed.hostname or "")
else:
    print("")
PY
}

DB_HOST=$(host_from_url)
DB_PORT=${DB_PORT:-5432}

_wait_for_port() {
  local host="$1"; local port="$2"; local tries=0
  until nc -z "$host" "$port" >/dev/null 2>&1; do
    tries=$((tries+1))
    if [ "$tries" -gt 60 ]; then
      echo "Timed out waiting for $host:$port"
      exit 1
    fi
    echo "Waiting for $host:$port..."
    sleep 1
  done
}

# If DATABASE_URL provided, try to discover host + wait
if [ -n "$DB_HOST" ]; then
  _wait_for_port "$DB_HOST" "$DB_PORT"
fi

# Optionally run DB migrations (Flask-Migrate / alembic)
if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  echo "Running database migrations (flask db upgrade)..."
  # Use Flask CLI. Ensure FLASK_APP is set to factory: backend:create_app
  export FLASK_APP=backend:create_app
  flask db upgrade || echo "flask db upgrade failed (continuing)"
fi

# Exec the CMD (gunicorn...) as PID 1
echo "Starting server: $@"
exec "$@"
