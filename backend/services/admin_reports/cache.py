# ============================================================================
# backend/services/admin_reports/cache.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   TTL cache wrapper:
#     • Uses backend.utils.cache if present (Redis)
#     • Falls back to in-process TTL cache in dev
# ============================================================================

from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, Optional, Tuple, cast

_INPROC_CACHE: Dict[str, Tuple[float, Any]] = {}

def _now_ts() -> float:
    return datetime.utcnow().timestamp()

def cache_get(key: str) -> Optional[Any]:
    try:
        from backend.utils.cache import cache_get as redis_get  # type: ignore
        return cast(Any, redis_get)(key)
    except Exception:
        item = _INPROC_CACHE.get(key)
        if not item:
            return None
        expires_at, value = item
        if _now_ts() >= expires_at:
            _INPROC_CACHE.pop(key, None)
            return None
        return value

def cache_set(key: str, value: Any, ttl: int) -> None:
    try:
        from backend.utils.cache import cache_set as redis_set  # type: ignore
        redis_set_any = cast(Any, redis_set)
        try:
            redis_set_any(key, value, int(ttl))  # positional TTL (compat)
            return
        except TypeError:
            try:
                redis_set_any(key, value, ttl=int(ttl))
                return
            except TypeError:
                redis_set_any(key, value)
                return
    except Exception:
        _INPROC_CACHE[key] = (_now_ts() + float(int(ttl)), value)
