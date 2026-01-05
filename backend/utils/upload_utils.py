# ====================================================================
# backend/utils/upload_utils.py — Unified Upload Utilities
# ====================================================================
# FILE ROLE:
#   • Central upload validation + routing.
#   • Enforces allowed extensions and max sizes.
#   • Delegates the actual persistence to storage backends via get_storage().
#
# IMPORTANT:
#   • This module must remain backend-agnostic:
#     no filesystem code, no boto3 code, no S3 code here.
# ====================================================================

from __future__ import annotations

from typing import Optional, Set

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from backend.storage import get_storage

IMAGE_EXTENSIONS: Set[str] = {"png", "jpg", "jpeg", "gif", "webp"}
DOCUMENT_EXTENSIONS: Set[str] = {"pdf", "csv", "xlsx", "docx"}

MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB


def _extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower()


def _validate_file(file: FileStorage, allowed: Set[str]) -> None:
    if not file or not file.filename:
        raise ValueError("No file provided")

    filename = secure_filename(file.filename)
    if "." not in filename or _extension(filename) not in allowed:
        raise ValueError("Unsupported file type")


def save_image(
    file: Optional[FileStorage],
    *,
    folder: str = "images",
) -> Optional[str]:
    """
    Save an image via the configured storage backend.

    Returns:
      • public URL (str) if saved
      • None if no file was provided
    """
    if not file:
        return None

    _validate_file(file, IMAGE_EXTENSIONS)

    # Size check
    file.seek(0, 2)
    size = file.tell()
    file.seek(0)

    if size > MAX_IMAGE_SIZE:
        raise ValueError("Image exceeds 5MB limit")

    storage = get_storage()
    return storage.save(file, folder)


def save_file(
    file: Optional[FileStorage],
    *,
    folder: str,
    allowed_extensions: Set[str],
) -> Optional[str]:
    """
    Save a generic file via the configured storage backend.
    """
    if not file:
        return None

    _validate_file(file, allowed_extensions)

    storage = get_storage()
    return storage.save(file, folder)


def default_image_url() -> str:
    """
    Default public image URL (frontend can map this to a real asset).
    """
    return "/uploads/defaults/default.png"
