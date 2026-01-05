# ====================================================================
# ai_service/cache_keys.py — Typed Cache Keys (Backend-Compatible)
# ====================================================================
# FILE ROLE:
#   • Canonical, typed cache key builder for Redis caching.
#   • Can mirror backend’s key format to safely share Redis.
#   • Ensures deterministic hashing + stable key strings for reproducibility.
# ====================================================================

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional


class CacheNamespace(str, Enum):
    AGROCONNECT = "agroconnect"


class CacheService(str, Enum):
    BACKEND = "backend"
    AI = "ai"


class CacheKeyKind(str, Enum):
    AI_BASIC_PRED = "ai_basic_pred"
    AI_PRICE_PRED = "ai_price_pred"
    AI_DEMAND_PRED = "ai_demand_pred"
    AI_ARIMA_FORECAST = "ai_arima_forecast"
    AI_SEARCH_EVENT = "ai_search_event"

    AI_RECOMMENDATIONS = "ai_recommendations"
    AI_RANKINGS = "ai_rankings"
    AI_STOCK_ALERT_INPUTS = "ai_stock_alert_inputs"

    BACKEND_ANALYTICS = "backend_analytics"
    BACKEND_DTO = "backend_dto"


def _canonical_json(payload: Mapping[str, Any]) -> str:
    # Deterministic JSON representation
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _hash_payload(payload: Mapping[str, Any]) -> str:
    raw = _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CacheKey:
    namespace: CacheNamespace
    service: CacheService
    env: str
    kind: CacheKeyKind
    payload_hash: str
    model_version: str = "na"

    def to_str(self) -> str:
        return (
            f"{self.namespace.value}:{self.service.value}:{self.env}:"
            f"{self.model_version}:{self.kind.value}:{self.payload_hash}"
        )

    # Optional: structural-typing support for AsyncJsonCache keys
    def as_redis_key(self) -> str:
        return self.to_str()


def build_cache_key(
    *,
    kind: CacheKeyKind,
    payload: Mapping[str, Any],
    env: str,
    service: CacheService,
    model_version: Optional[str] = None,
    namespace: CacheNamespace = CacheNamespace.AGROCONNECT,
) -> CacheKey:
    return CacheKey(
        namespace=namespace,
        service=service,
        env=env,
        model_version=(model_version or "na"),
        kind=kind,
        payload_hash=_hash_payload(payload),
    )
