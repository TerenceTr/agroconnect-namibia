# =====================================================================
# ai_service/services/circuit.py — Shared Circuit Breaker Defaults
# =====================================================================
# FILE ROLE:
#   • Provides a sane default config builder for circuit breaker
#   • Avoids creating Redis clients here (app.py should own pooling)
# =====================================================================

from __future__ import annotations

from ai_service.services.circuit_breaker import CircuitBreakerConfig


def default_breaker_config() -> CircuitBreakerConfig:
    """
    Central place to tune breaker thresholds across the AI service.

    app.py can import this to keep config consistent.
    """
    return CircuitBreakerConfig(
        window_seconds=60,
        min_requests=20,
        error_rate_threshold=0.35,
        cooldown_seconds=60,
    )
