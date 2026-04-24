# ==============================================================================
# ai_service/Dockerfile — AgroConnect Namibia AI Microservice
# ------------------------------------------------------------------------------
# FILE ROLE:
#   Production-grade container image for the AI microservice (FastAPI/Uvicorn).
#
# GOALS:
#   ✅ Strict production hygiene (prod image installs ONLY requirements.txt)
#   ✅ Non-root runtime user
#   ✅ Healthcheck
#   ✅ Multi-stage build keeps build tools out of runtime image
#   ✅ Optional "dev" target for CI/testing (installs requirements-dev.txt)
#
# HOW TO BUILD:
#   Production (default):
#     docker build -t agroconnect-ai:prod .
#
#   Dev/Test image (includes dev/test tools):
#     docker build --target dev -t agroconnect-ai:dev .
#
# HOW TO RUN:
#   docker run -p 8001:8001 agroconnect-ai:prod
# ==============================================================================


# ------------------------------------------------------------------------------
# Stage 1: builder — downloads/builds wheels (no runtime image bloat)
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS builder
LABEL org.opencontainers.image.title="AgroConnect AI Service (builder)"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /srv/ai

# Minimal OS deps for downloading and (rarely) building wheels
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better build caching
COPY requirements.txt /srv/ai/requirements.txt
COPY requirements-dev.txt /srv/ai/requirements-dev.txt

RUN python -m pip install --upgrade pip setuptools wheel \
    # Build wheelhouse for strict, repeatable installs in runtime stage
    && python -m pip wheel --wheel-dir /wheels -r /srv/ai/requirements.txt


# ------------------------------------------------------------------------------
# Stage 2: runtime (production) — installs ONLY prod deps from wheelhouse
# ------------------------------------------------------------------------------
FROM python:3.11-slim AS prod
LABEL org.opencontainers.image.title="AgroConnect AI Service"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Ensures `import ai_service...` works regardless of run directory
ENV PYTHONPATH=/srv/ai

WORKDIR /srv/ai

# Runtime OS deps only (keep small)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd --create-home --no-log-init --shell /bin/false aiuser

# Copy wheels + prod requirements
COPY --from=builder /wheels /wheels
COPY requirements.txt /srv/ai/requirements.txt

# Install prod dependencies ONLY (no dev tooling)
RUN python -m pip install --upgrade pip \
    && python -m pip install --no-cache-dir --no-index --find-links=/wheels -r /srv/ai/requirements.txt \
    && rm -rf /wheels

# Copy application code last (best caching)
COPY . /srv/ai

# Switch to non-root user at runtime
USER aiuser

EXPOSE 8001

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=5 \
  CMD curl -f http://127.0.0.1:8001/health || exit 1

# IMPORTANT:
#   Use module path now that code is packaged under ai_service/
CMD ["uvicorn", "ai_service.app:app", "--host", "0.0.0.0", "--port", "8001", "--limit-concurrency", "100"]


# ------------------------------------------------------------------------------
# Stage 3: dev — optional target with dev/test tooling (NOT for production)
# ------------------------------------------------------------------------------
FROM prod AS dev
LABEL org.opencontainers.image.title="AgroConnect AI Service (dev)"

# Temporarily elevate to install dev deps (then drop back to aiuser)
USER root

# Copy dev requirements and install (includes prod via -r requirements.txt inside)
COPY requirements-dev.txt /srv/ai/requirements-dev.txt

RUN python -m pip install --no-cache-dir -r /srv/ai/requirements-dev.txt

USER aiuser
