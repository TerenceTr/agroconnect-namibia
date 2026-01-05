# ====================================================================
# backend/utils/presence_store.py — Simple Presence Store (DEV-SAFE)
# ====================================================================
# FILE ROLE:
#   • Tracks "last seen" timestamps for logged-in users.
#   • Enables Admin dashboard online/offline view.
#
# DESIGN:
#   • In-memory store (single-process dev friendly).
#   • For multi-worker production: replace with Redis storage.
# ====================================================================

from __future__ import annotations

import time
from typing import Dict, Set
from uuid import UUID

# user_id (str) -> last_seen_epoch_seconds (float)
_last_seen: Dict[str, float] = {}


def mark_seen(user_id: UUID) -> None:
    """Mark a user as active 'now'."""
    _last_seen[str(user_id)] = time.time()


def is_online(user_id: UUID, *, threshold_seconds: int = 300) -> bool:
    """
    Consider user online if last seen within threshold.
    Default threshold: 5 minutes.
    """
    key = str(user_id)
    last = _last_seen.get(key)
    if last is None:
        return False
    return (time.time() - last) <= float(threshold_seconds)


def online_user_ids(*, threshold_seconds: int = 300) -> Set[str]:
    """Return the set of user_id strings considered online."""
    now = time.time()
    out: Set[str] = set()
    for uid, last in list(_last_seen.items()):
        if (now - last) <= float(threshold_seconds):
            out.add(uid)
    return out
