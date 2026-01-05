# ====================================================================
# backend/storage/__init__.py — Storage Factory (OPTIONAL S3 SAFE)
# ====================================================================
# FILE ROLE:
#   • Central storage factory for uploads
#   • Chooses backend based on env var STORAGE_BACKEND
#   • Avoids importing optional dependencies (boto3) unless needed
#
# ENV:
#   STORAGE_BACKEND=local (default) OR s3
# ====================================================================

from __future__ import annotations

import os

from backend.storage.base import StorageBackend
from backend.storage.local import LocalStorage


def get_storage() -> StorageBackend:
    """
    Returns the configured storage backend.

    IMPORTANT:
      We import S3Storage lazily so the app can run without boto3
      when using local storage.
    """
    backend = os.getenv("STORAGE_BACKEND", "local").lower().strip()

    if backend == "s3":
        try:
            from backend.storage.s3 import S3Storage  # lazy import
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "STORAGE_BACKEND is set to 's3' but required packages are missing. "
                "Install 'boto3' (and botocore) or set STORAGE_BACKEND=local."
            ) from exc

        return S3Storage()

    # Default: local filesystem storage
    return LocalStorage()
