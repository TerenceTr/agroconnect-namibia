# =====================================================================
# ai_service/services/_backend.py — Backend API Client
# =====================================================================

from __future__ import annotations
from typing import Any, Dict, Optional

import httpx

from ai_service.config import settings
from ai_service.services.circuit_breaker import RedisCircuitBreaker
from ai_service.services.base import service_logger, timed, retry

_backend_breaker: Optional[RedisCircuitBreaker] = None


def wire_backend_breaker(breaker: RedisCircuitBreaker) -> None:
    """Inject shared breaker from app.py."""
    global _backend_breaker
    _backend_breaker = breaker


class BackendClientError(RuntimeError):
    """Backend call failed."""


@retry(attempts=3, delay_seconds=0.5)
@timed("backend.get")
async def backend_get(
    path: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    breaker_name: str = "backend",
) -> Dict[str, Any]:

    if _backend_breaker and await _backend_breaker.is_open(breaker_name):
        raise BackendClientError(f"Circuit open: {breaker_name}")

    url = f"{settings.backend_api_url.rstrip('/')}{path}"
    headers = {"X-Service-Token": settings.backend_service_token}

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(url, params=params, headers=headers)
            resp.raise_for_status()

            payload = resp.json()
            if not isinstance(payload, dict):
                raise BackendClientError("Invalid backend response")

            if _backend_breaker:
                await _backend_breaker.record_success(breaker_name)

            return payload

    except Exception as exc:
        if _backend_breaker:
            await _backend_breaker.record_failure(breaker_name)

        service_logger.exception("Backend GET failed")
        raise BackendClientError(str(exc)) from exc
