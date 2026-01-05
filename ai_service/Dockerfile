# ai_service/Dockerfile
# ---------------------------------------------------------------------
# FILE ROLE:
#   Production-ready container image for the AI microservice.
#   Uses non-root user + healthcheck + slim base image.
# ---------------------------------------------------------------------

FROM python:3.11-slim AS base
LABEL org.opencontainers.image.title="AgroConnect AI Service"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Ensures `import ai_service...` works regardless of run directory
ENV PYTHONPATH=/srv/ai

WORKDIR /srv/ai

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --no-log-init --shell /bin/false aiuser
USER aiuser

COPY --chown=aiuser:aiuser requirements.txt /srv/ai/requirements.txt

RUN python -m pip install --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir -r /srv/ai/requirements.txt

COPY --chown=aiuser:aiuser . /srv/ai

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
  CMD curl -f http://127.0.0.1:8001/health || exit 1

# IMPORTANT:
#   Use module path now that code is packaged under ai_service/
CMD ["uvicorn", "ai_service.app:app", "--host", "0.0.0.0", "--port", "8001", "--limit-concurrency", "100"]
