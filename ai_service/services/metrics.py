# =====================================================================
# ai_service/services/metrics.py — Lightweight Metrics Hooks
# =====================================================================
# FILE ROLE:
#   • Centralized counters for service observability
#   • Safe for async usage, local dev, and unit tests
#   • Zero external dependencies
#
# NOTE:
#   • This is intentionally simple.
#   • Later you can export these to Prometheus/OpenTelemetry.
# =====================================================================

from __future__ import annotations

from collections import defaultdict
from typing import DefaultDict


_counters: DefaultDict[str, int] = defaultdict(int)


def inc(metric: str, value: int = 1) -> None:
    """Increment a named counter."""
    _counters[metric] += int(value)


def get(metric: str) -> int:
    """Get a single counter value."""
    return int(_counters.get(metric, 0))


def snapshot() -> dict[str, int]:
    """Return all counters as a plain dict."""
    return dict(_counters)
