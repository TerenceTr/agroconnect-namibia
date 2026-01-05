# ====================================================================
# backend/storage/base.py — Storage Backend Interface
# ====================================================================
# FILE ROLE:
#   • Defines a minimal interface for file storage backends.
#   • Keeps upload_utils independent of local filesystem or S3.
# ====================================================================

from __future__ import annotations

from abc import ABC, abstractmethod
from werkzeug.datastructures import FileStorage


class StorageBackend(ABC):
    """
    Abstract interface for all storage backends.
    """

    @abstractmethod
    def save(self, file: FileStorage, folder: str) -> str:
        """
        Persist a file and return a public URL.
        """
        raise NotImplementedError

    def generate_signed_url(self, key: str, *, expires: int = 900) -> str:
        """
        Optional: signed URL support (S3-like backends).
        Local backend can ignore or raise.
        """
        raise NotImplementedError
