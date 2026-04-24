# ============================================================================
# backend/services/token_service.py — Refresh token issue / rotate / revoke
# ----------------------------------------------------------------------------
# FILE ROLE:
#   Central token lifecycle service for:
#     • issuing access + refresh tokens
#     • persisting refresh token hashes
#     • rotation on /refresh
#     • revocation on /logout
#     • revoke-all on /logout-all
# ============================================================================

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import select, update

from backend.database.db import db
from backend.models.refresh_token import RefreshToken
from backend.models.user import User
from backend.utils.jwt_utils import jwt_decode, jwt_encode


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    s = str(value).strip()
    return s if s else None


def _as_uuid(value: Any) -> Optional[uuid.UUID]:
    if value is None:
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value).strip())
    except Exception:
        return None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _user_id(user: User) -> Optional[uuid.UUID]:
    raw = getattr(user, "id", None) or getattr(user, "user_id", None)
    return _as_uuid(raw)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def _refresh_expiry(days: int = 30) -> datetime:
    return _utcnow() + timedelta(days=max(1, int(days)))


def issue_access_token(user: User, *, hours: int = 1) -> str:
    uid = _user_id(user)
    if uid is None:
        raise ValueError("User id is required for token issuance")
    return jwt_encode({"sub": str(uid)}, purpose="access", hours=max(1, int(hours)))


def _build_refresh_token(user: User, *, days: int = 30) -> tuple[str, datetime]:
    uid = _user_id(user)
    if uid is None:
        raise ValueError("User id is required for refresh token issuance")

    expires_at = _refresh_expiry(days)
    jti = str(uuid.uuid4())

    token = jwt_encode(
        {"sub": str(uid), "jti": jti},
        purpose="refresh",
        hours=max(1, int(days)) * 24,
    )
    return token, expires_at


def _persist_refresh_token(
    *,
    user_id: uuid.UUID,
    raw_refresh_token: str,
    expires_at: datetime,
) -> RefreshToken:
    entry = RefreshToken()
    entry.user_id = user_id
    entry.token_hash = _hash_token(raw_refresh_token)
    entry.expires_at = expires_at
    db.session.add(entry)
    return entry


def issue_token_pair(
    user: User,
    *,
    refresh_days: int = 30,
    commit: bool = True,
) -> dict[str, str]:
    """
    Issue:
      - short-lived access token
      - persisted refresh token
    """
    uid = _user_id(user)
    if uid is None:
        raise ValueError("User id is required")

    access = issue_access_token(user, hours=1)
    refresh, expires_at = _build_refresh_token(user, days=refresh_days)

    _persist_refresh_token(
        user_id=uid,
        raw_refresh_token=refresh,
        expires_at=expires_at,
    )

    if commit:
        db.session.commit()

    return {
        "accessToken": access,
        "refreshToken": refresh,
        "token": access,  # backward compatibility
    }


def validate_refresh_token(raw_refresh_token: str) -> Optional[tuple[User, RefreshToken]]:
    token = _safe_str(raw_refresh_token)
    if not token:
        return None

    try:
        decoded = jwt_decode(token)
    except Exception:
        return None

    if decoded.get("purpose") != "refresh":
        return None

    uid = _as_uuid(decoded.get("sub"))
    if uid is None:
        return None

    user = db.session.get(User, uid)
    if user is None or not bool(getattr(user, "is_active", True)):
        return None

    token_hash = _hash_token(token)

    stmt = (
        select(RefreshToken)
        .where(RefreshToken.token_hash == token_hash)
        .limit(1)
    )
    record = db.session.scalars(stmt).first()

    if record is None:
        return None
    if record.user_id != uid:
        return None
    if record.is_revoked or record.is_expired:
        return None

    return user, record


def rotate_refresh_token(
    raw_refresh_token: str,
    *,
    refresh_days: int = 30,
    commit: bool = True,
) -> Optional[tuple[User, dict[str, str]]]:
    """
    Refresh-token rotation:
      - validate current persisted token
      - revoke old token
      - issue fresh access token
      - issue fresh persisted refresh token
    """
    validated = validate_refresh_token(raw_refresh_token)
    if validated is None:
        return None

    user, old_record = validated
    uid = _user_id(user)
    if uid is None:
        return None

    old_record.revoke()
    db.session.add(old_record)

    access = issue_access_token(user, hours=1)
    new_refresh, expires_at = _build_refresh_token(user, days=refresh_days)
    _persist_refresh_token(
        user_id=uid,
        raw_refresh_token=new_refresh,
        expires_at=expires_at,
    )

    if commit:
        db.session.commit()

    return user, {
        "accessToken": access,
        "refreshToken": new_refresh,
        "token": access,
    }


def revoke_refresh_token(
    raw_refresh_token: str,
    *,
    commit: bool = True,
) -> bool:
    validated = validate_refresh_token(raw_refresh_token)
    if validated is None:
        return False

    _, record = validated
    record.revoke()
    db.session.add(record)

    if commit:
        db.session.commit()

    return True


def revoke_all_user_refresh_tokens(
    user_id: Any,
    *,
    commit: bool = True,
) -> int:
    uid = _as_uuid(user_id)
    if uid is None:
        return 0

    now = _utcnow()

    stmt = (
        update(RefreshToken)
        .where(
            RefreshToken.user_id == uid,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )

    result = db.session.execute(stmt)
    affected = int(result.rowcount or 0)

    if commit:
        db.session.commit()

    return affected