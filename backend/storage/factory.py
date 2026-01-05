# ====================================================================
# backend/storage/factory.py — Storage Backend Selector
# ====================================================================

import os

from backend.storage.local import LocalStorage
from backend.storage.s3 import S3Storage


def get_storage():
    backend = os.getenv("STORAGE_BACKEND", "local").lower()

    if backend == "s3":
        return S3Storage()

    return LocalStorage()
