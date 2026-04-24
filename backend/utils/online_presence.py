# ============================================================================
# backend/utils/online_presence.py — Online Presence Tracking (In-Memory)
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Track which users are currently online or recently active.
#
# DESIGN:
#   • Updated on every authenticated request
#   • No database migration required
#   • Best-effort (resets on server restart)
#
# USED BY:
#   • Admin dashboard (Login Status card)
# ============================================================================

from __future__ import annotations

import uuid
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

_LOCK = threading.Lock()
_LAST_SEEN: Dict[uuid.UUID, datetime] = {}


def mark_seen(user_id: uuid.UUID) -> None:
    """Mark a user as active (UTC)."""
    try:
        uid = user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(str(user_id))
    except Exception:
        return

    with _LOCK:
        _LAST_SEEN[uid] = datetime.utcnow()


def snapshot(*, limit: int = 12, online_minutes: int = 10) -> List[Tuple[uuid.UUID, datetime, bool]]:
    """
    Returns:
      [(user_id, last_seen_utc, is_online)]
    """
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=online_minutes)

    with _LOCK:
        rows = list(_LAST_SEEN.items())

    rows.sort(key=lambda r: r[1], reverse=True)

    result = []
    for uid, ts in rows[:limit]:
        result.append((uid, ts, ts >= cutoff))

    return result


def build_payload(*, db_session, user_model, limit: int = 12, online_minutes: int = 10):
    """
    UI-ready payload:
      {
        window_minutes,
        online: [...],
        recent: [...]
      }
    """
    rows = snapshot(limit=limit, online_minutes=online_minutes)
    user_ids = [uid for uid, _, _ in rows]

    users = {}
    if user_ids:
        try:
            q = db_session.query(user_model).filter(user_model.id.in_(user_ids))
            for u in q.all():
                users[u.id] = u
        except Exception:
            pass

    online, recent = [], []

    for uid, ts, is_online in rows:
        u = users.get(uid)
        item = {
            "user_id": str(uid),
            "full_name": getattr(u, "full_name", None) if u else None,
            "email": getattr(u, "email", None) if u else None,
            "role": getattr(u, "role", None) if u else None,
            "last_seen": ts.isoformat(),
            "is_online": bool(is_online),
        }
        recent.append(item)
        if is_online:
            online.append(item)

    return {
        "window_minutes": online_minutes,
        "online": online,
        "recent": recent,
    }
