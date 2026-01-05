# ====================================================================
# backend/storage/local.py — Local Disk Storage Backend (DEV DEFAULT)
# ====================================================================
# FILE ROLE:
#   • Saves uploads to backend/uploads/<folder>/...
#   • Returns a public URL served by backend/app.py route:
#       GET /api/uploads/public_images/<filename>
#
# NOTE:
#   • This is the safe default for local development.
#   • No external dependencies required.
# ====================================================================

from __future__ import annotations

import os
import uuid
from typing import Final

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from backend.storage.base import StorageBackend

UPLOAD_ROOT_ENV: Final[str] = "UPLOAD_ROOT"


class LocalStorage(StorageBackend):
    """
    Store files locally under UPLOAD_ROOT (defaults to <project>/backend/uploads).
    """

    def __init__(self) -> None:
        # Allow override by env var (useful in docker)
        default_root = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads")
        self.root = os.getenv(UPLOAD_ROOT_ENV, default_root)

    def save(self, file: FileStorage, folder: str) -> str:
        """
        Save file to disk and return a public URL.
        """
        filename = secure_filename(file.filename or "")
        ext = os.path.splitext(filename)[1].lower()
        unique = f"{uuid.uuid4().hex}{ext}"

        target_dir = os.path.join(self.root, folder)
        os.makedirs(target_dir, exist_ok=True)

        abs_path = os.path.join(target_dir, unique)
        file.save(abs_path)

        # Your app.py serves:
        # /api/uploads/public_images/<filename>
        #
        # If folder != "public_images", you can either:
        # 1) add more routes, or
        # 2) standardize images to public_images.
        #
        # For now, return a simple folder-based URL:
        return f"/api/uploads/{folder}/{unique}"
