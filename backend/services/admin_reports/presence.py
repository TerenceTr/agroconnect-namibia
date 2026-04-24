# ============================================================================
# backend/services/admin_reports/presence.py
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Admin presence builder (best-effort):
#     • returns "online" and "recent" admins based on last_seen-like columns
# ============================================================================

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import inspect, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from backend.services.admin_reports.cache import cache_get, cache_set

try:
    from backend.models.user import User  # type: ignore
except Exception:
    User = None  # type: ignore

def _iso(dt: Optional[Any]) -> Optional[str]:
    if dt is None:
        return None
    try:
        return dt.isoformat()
    except Exception:
        return None

def _has_column(model: Any, column_name: str) -> bool:
    try:
        mapper = inspect(model)
        return bool(getattr(mapper, "columns", None)) and column_name in mapper.columns
    except Exception:
        return False

def _pick_first_col(model: Any, candidates: List[str]) -> Optional[str]:
    for name in candidates:
        if _has_column(model, name):
            return name
    return None

def _col(model: Any, column_name: str) -> Any:
    return getattr(model, column_name)

def _admin_filter(stmt: Any) -> Any:
    if User is None:
        return stmt
    if _has_column(User, "role"):
        return stmt.where(_col(User, "role") == "admin")
    if _has_column(User, "is_admin"):
        return stmt.where(_col(User, "is_admin").is_(True))
    if _has_column(User, "user_type"):
        return stmt.where(_col(User, "user_type") == "admin")
    return stmt

def build_admin_presence(
    *,
    session: Session,
    limit: int = 12,
    online_minutes: int = 10,
    ttl: int = 60,
    refresh: bool = False,
) -> Dict[str, Any]:
    cache_key = f"admin_presence:limit={limit}:window={online_minutes}"
    if ttl > 0 and not refresh:
        cached = cache_get(cache_key)
        if isinstance(cached, dict):
            return cached

    cutoff = datetime.utcnow() - timedelta(minutes=online_minutes)

    online: List[Dict[str, Any]] = []
    recent: List[Dict[str, Any]] = []

    if User is not None:
        try:
            last_seen_col = _pick_first_col(User, ["last_seen", "updated_at", "last_login", "created_at"])
            pk_col = _pick_first_col(User, ["id", "user_id"])

            stmt = select(User)
            stmt = _admin_filter(stmt)
            if last_seen_col:
                stmt = stmt.order_by(_col(User, last_seen_col).desc())
            stmt = stmt.limit(limit)

            users = session.execute(stmt).scalars().all()

            for u in users:
                name = (
                    getattr(u, "full_name", None)
                    or getattr(u, "name", None)
                    or getattr(u, "username", None)
                    or getattr(u, "email", None)
                    or "Admin"
                )
                email = getattr(u, "email", None)
                last_seen_val = getattr(u, last_seen_col, None) if last_seen_col else None

                item = {
                    "id": getattr(u, pk_col, None) if pk_col else None,
                    "full_name": str(name),
                    "email": str(email) if email else None,
                    "last_seen": _iso(last_seen_val),
                }

                if isinstance(last_seen_val, datetime) and last_seen_val >= cutoff:
                    online.append(item)
                else:
                    recent.append(item)
        except SQLAlchemyError:
            online, recent = [], []

    payload = {
        "window_minutes": online_minutes,
        "online": online,
        "recent": recent,
        "generated_at": _iso(datetime.utcnow()),
        "cached_ttl_seconds": ttl,
    }

    if ttl > 0:
        cache_set(cache_key, payload, ttl)

    return payload
