# =====================================================================
# ai_service/services/prometheus_exporter.py — Prometheus Drop-in
# =====================================================================
# FILE ROLE:
#   • Provides Prometheus exposition endpoint as a sub-app
#   • Optional dependency behavior: safe if prometheus_client is missing
#
# NOTE:
#   This does NOT replace your existing JSON /metrics endpoint.
# =====================================================================

from __future__ import annotations

from fastapi import FastAPI, Response

try:
    from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
except Exception:  # pragma: no cover
    CollectorRegistry = None  # type: ignore
    Counter = None  # type: ignore
    Histogram = None  # type: ignore
    generate_latest = None  # type: ignore
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"  # type: ignore


prometheus_metrics_app = FastAPI(title="Prometheus Metrics")

_registry = CollectorRegistry() if CollectorRegistry is not None else None

CACHE_HIT = Counter("ai_cache_hit_total", "Total cache hits", registry=_registry) if Counter else None
CACHE_MISS = Counter("ai_cache_miss_total", "Total cache misses", registry=_registry) if Counter else None

BACKEND_GET_LATENCY = (
    Histogram(
        "ai_backend_get_latency_seconds",
        "Latency for backend GET calls",
        buckets=(0.05, 0.1, 0.2, 0.5, 1, 2, 5, 10, 20),
        registry=_registry,
    )
    if Histogram
    else None
)


@prometheus_metrics_app.get("/")
async def prom_metrics() -> Response:
    """Prometheus scrape endpoint (mount at /metrics/prom)."""
    if generate_latest is None or _registry is None:
        return Response("prometheus_client not installed\n", media_type="text/plain")
    payload = generate_latest(_registry)
    return Response(payload, media_type=CONTENT_TYPE_LATEST)
