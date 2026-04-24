# ====================================================================
# backend/services/presence_store.py — In-Memory Presence (Online/Offline)
# ====================================================================
# FILE ROLE:
#   Lightweight in-memory store of "last seen" timestamps per user.
#
# PURPOSE:
#   • Allows admin to show Online/Offline users without a DB schema change
#   • Updated via /api/presence/ping (JWT user ping)
#   • Cleared immediately on explicit logout for accurate online counts
#
# LIMITATIONS:
#   • In-memory store is per-process:
#       - OK for local dev / single worker
#       - NOT reliable across multiple gunicorn workers / pods
#   • For production multi-worker: use Redis/shared presence as primary
#
# CONFIG:
#   PRESENCE_TTL_SECONDS: "online" threshold (default 120 seconds)
# ====================================================================

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Dict, List, Tuple

PRESENCE_TTL_SECONDS = int(os.environ.get("PRESENCE_TTL_SECONDS", "120"))

# Internal store: user_id (str) -> last seen (UTC datetime)
_last_seen: Dict[str, datetime] = {}
_lock = threading.Lock()


def _now() -> datetime:
    """UTC 'now' helper."""
    return datetime.now(timezone.utc)


def touch(user_id: str) -> None:
    """
    Mark user as seen 'now'.

    NOTE:
      user_id is stored as str so it is stable across JSON/API boundaries.
    """
    uid = str(user_id)
    with _lock:
        _last_seen[uid] = _now()


def mark_offline(user_id: str) -> None:
    """Remove a user from the live in-memory presence set immediately."""
    uid = str(user_id)
    with _lock:
        _last_seen.pop(uid, None)


def snapshot() -> Tuple[Dict[str, str], List[str]]:
    """
    Build a snapshot for admin dashboards.

    Returns:
      (last_seen_iso_map, online_ids)

    last_seen_iso_map:
      { user_id: "2026-01-07T12:34:56.789+00:00", ... }

    online_ids:
      list of user_id strings considered "online" within TTL.
    """
    now = _now()
    online_ids: List[str] = []

    # Purge very old entries + compute online list
    # We keep a larger eviction window to prevent unbounded growth.
    hard_evict_seconds = PRESENCE_TTL_SECONDS * 10

    with _lock:
        for uid, ts in list(_last_seen.items()):
            age = (now - ts).total_seconds()

            # Hard eviction (very stale)
            if age > hard_evict_seconds:
                _last_seen.pop(uid, None)
                continue

            # Online threshold
            if age <= PRESENCE_TTL_SECONDS:
                online_ids.append(uid)

        last_seen_iso = {uid: ts.isoformat() for uid, ts in _last_seen.items()}

    return last_seen_iso, online_ids


def is_online(user_id: str) -> bool:
    """Return True if a user is online within TTL; otherwise False."""
    uid = str(user_id)
    with _lock:
        ts = _last_seen.get(uid)
    if not ts:
        return False
    return (_now() - ts).total_seconds() <= PRESENCE_TTL_SECONDS