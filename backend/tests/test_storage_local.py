# ====================================================================
# tests/storage/test_local_storage.py — LocalStorage Unit Tests
# ====================================================================
# FILE ROLE:
#   • Unit tests for LocalStorage backend
#   • Ensures files are saved correctly to filesystem
#   • Validates returned public URL format
#
# WHY THIS TEST EXISTS:
#   • Prevents regressions in file upload logic
#   • Confirms Docker + volume paths behave correctly
#   • Required for CI safety before enabling S3/MinIO
# ====================================================================

from __future__ import annotations

import io  # ✅ FIX: io must be imported explicitly
from pathlib import Path

import pytest
from werkzeug.datastructures import FileStorage

from backend.storage.local import LocalStorage


# ====================================================================
# TEST: Save file locally
# ====================================================================
def test_local_storage_save(tmp_path: Path, app):
    """
    Verify that LocalStorage.save():
      • Stores file in uploads/<folder>/
      • Generates UUID-based filename
      • Returns web-accessible URL
    """

    storage = LocalStorage()

    # ------------------------------------------------------------
    # Override Flask root_path safely for this test
    # ------------------------------------------------------------
    app.root_path = str(tmp_path)

    # ------------------------------------------------------------
    # Create in-memory file upload (no real filesystem dependency)
    # ------------------------------------------------------------
    file = FileStorage(
        stream=io.BytesIO(b"hello world"),
        filename="test.txt",
        content_type="text/plain",
    )

    # ------------------------------------------------------------
    # Execute save inside Flask app context
    # ------------------------------------------------------------
    with app.app_context():
        path = storage.save(file, folder="tests")

    # ------------------------------------------------------------
    # Assertions
    # ------------------------------------------------------------
    assert path.startswith("/uploads/tests/")
    assert path.endswith(".txt")

    # Ensure file was actually written
    saved_file = tmp_path / "uploads" / "tests"
    assert any(saved_file.iterdir()), "File was not written to disk"
