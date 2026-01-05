# =====================================================================
# ai_service/tests/test_openapi_snapshot_hash.py — OpenAPI Hash Snapshot
# =====================================================================
# ROLE:
#   • Computes deterministic SHA256 of the OpenAPI schema
#   • Compares against checked-in snapshot file
#
# CI READY:
#   • Fails if schema changes unexpectedly
#   • Update snapshot intentionally using:
#       UPDATE_OPENAPI_SNAPSHOT=1 pytest -q
# =====================================================================

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from ai_service.app import app

SNAPSHOT_FILE = Path(__file__).parent / "openapi_schema.sha256"


def _canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def test_openapi_sha256_snapshot():
    schema = app.openapi()
    digest = _sha256(_canonical_json(schema))

    if os.getenv("UPDATE_OPENAPI_SNAPSHOT", "").strip() in {"1", "true", "yes"}:
        SNAPSHOT_FILE.write_text(digest + "\n", encoding="utf-8")

    assert SNAPSHOT_FILE.exists(), (
        "Missing OpenAPI snapshot file. "
        "Run: UPDATE_OPENAPI_SNAPSHOT=1 pytest -q"
    )

    expected = SNAPSHOT_FILE.read_text(encoding="utf-8").strip()
    assert digest == expected, (
        "OpenAPI schema hash changed! If intentional, update snapshot via:\n"
        "  UPDATE_OPENAPI_SNAPSHOT=1 pytest -q"
    )
