# ====================================================================
# backend/services/presence_store.py — In-Memory Presence (Online/Offline)
# ====================================================================
# FILE ROLE:
#   Keeps a lightweight record of "last seen" timestamps for users.
#
# PURPOSE:
#   • Enables admin to view Online/Offline users without needing DB schema
#   • Updated via /api/presence/ping (JWT user ping)
#
# NOTE:
#   In-memory store is fine for single-process dev.
#   For multi-worker production, move this to Redis.
# ====================================================================

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Dict, Tuple

PRESENCE_TTL_SECONDS = int(os.environ.get("PRESENCE_TTL_SECONDS", "120"))

_last_seen: Dict[str, datetime] = {}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def touch(user_id: str) -> None:
    """Mark user as seen 'now'."""
    _last_seen[str(user_id)] = _now()


def snapshot() -> Tuple[Dict[str, str], list[str]]:
    """
    Returns:
      (last_seen_iso_map, online_ids)
    """
    now = _now()
    online_ids: list[str] = []

    # purge + compute online
    for uid, ts in list(_last_seen.items()):
        age = (now - ts).total_seconds()
        if age > (PRESENCE_TTL_SECONDS * 10):
            _last_seen.pop(uid, None)
            continue
        if age <= PRESENCE_TTL_SECONDS:
            online_ids.append(uid)

    last_seen_iso = {uid: ts.isoformat() for uid, ts in _last_seen.items()}
    return last_seen_iso, online_ids


def is_online(user_id: str) -> bool:
    ts = _last_seen.get(str(user_id))
    if not ts:
        return False
    return (_now() - ts).total_seconds() <= PRESENCE_TTL_SECONDS
