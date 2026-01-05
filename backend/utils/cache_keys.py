# ====================================================================
# Typed Cache Keys
# backend/utils/cache_keys.py
# ====================================================================
# ROLE:
#   • Defines a single, stable cache key format used across the system
#   • Provides typed "key kinds" to prevent ad-hoc string keys
#   • Ensures reproducible keys via canonical JSON hashing
#
# WHY THIS MATTERS:
#   • Backend + AI can safely share Redis without collisions
#   • Model version rollouts can isolate cache entries per model version
#   • Typed keys make debugging + invalidation predictable
# ====================================================================

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Optional


class CacheNamespace(str, Enum):
    """High-level namespaces to avoid collisions across apps/services."""
    AGROCONNECT = "agroconnect"


class CacheService(str, Enum):
    """Which service created/owns the cache entry."""
    BACKEND = "backend"
    AI = "ai"


class CacheKeyKind(str, Enum):
    """
    Typed categories of cache keys.

    Add new kinds here (instead of inventing random strings in code).
    """
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
    """
    Canonical JSON encoding:
      • stable key ordering
      • no whitespace
      • safe for hashing and cross-service reproducibility
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _hash_payload(payload: Mapping[str, Any]) -> str:
    raw = _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CacheKey:
    """
    Stable cache key format:

      {namespace}:{service}:{env}:{model_version}:{kind}:{sha256}

    Notes:
      • env is included to avoid dev/prod collisions if sharing Redis.
      • model_version can be "na" for backend-only keys.
    """
    namespace: CacheNamespace
    service: CacheService
    env: str
    kind: CacheKeyKind
    payload_hash: str
    model_version: str = "na"

    def to_str(self) -> str:
        return f"{self.namespace.value}:{self.service.value}:{self.env}:{self.model_version}:{self.kind.value}:{self.payload_hash}"


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
