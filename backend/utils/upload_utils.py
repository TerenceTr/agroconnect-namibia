# ====================================================================
# backend/utils/upload_utils.py — Unified Upload Utilities
# ====================================================================
# FILE ROLE:
#   • Central upload validation + routing.
#   • Enforces allowed extensions and max sizes.
#   • Delegates persistence to storage backends via get_storage().
#
# IMPORTANT:
#   • Backend-agnostic: no filesystem code, no boto3 code, no S3 code here.
# ====================================================================

from __future__ import annotations

from typing import Optional, Set

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename

from backend.storage import get_storage

IMAGE_EXTENSIONS: Set[str] = {"png", "jpg", "jpeg", "gif", "webp"}
DOCUMENT_EXTENSIONS: Set[str] = {"pdf", "csv", "xlsx", "docx"}

MAX_IMAGE_SIZE = 5 * 1024 * 1024  # 5 MB
MAX_DOCUMENT_SIZE = 20 * 1024 * 1024  # 20 MB


def _extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower()


def _validate_file(file: FileStorage, allowed: Set[str]) -> None:
    if not file or not file.filename:
        raise ValueError("No file provided")

    filename = secure_filename(file.filename)
    if "." not in filename or _extension(filename) not in allowed:
        raise ValueError("Unsupported file type")


def _size_of(file: FileStorage) -> int:
    file.stream.seek(0, 2)
    size = int(file.stream.tell() or 0)
    file.stream.seek(0)
    return size


def save_image(
    file: Optional[FileStorage],
    *,
    folder: str = "images",
) -> Optional[str]:
    """
    Save an image via the configured storage backend.

    Returns:
      • public URL/path (str) if saved
      • None if no file was provided
    """
    if not file:
        return None

    _validate_file(file, IMAGE_EXTENSIONS)

    size = _size_of(file)
    if size > MAX_IMAGE_SIZE:
        raise ValueError("Image exceeds 5MB limit")

    storage = get_storage()
    return storage.save(file, folder)


def save_file(
    file: Optional[FileStorage],
    *,
    folder: str,
    allowed_extensions: Set[str],
    max_size: int = MAX_DOCUMENT_SIZE,
) -> Optional[str]:
    """
    Save a generic file via the configured storage backend.
    """
    if not file:
        return None

    _validate_file(file, allowed_extensions)

    size = _size_of(file)
    if size > max_size:
        raise ValueError("File exceeds maximum allowed size")

    storage = get_storage()
    return storage.save(file, folder)


def default_image_url() -> str:
    """
    Default public image URL.
    Frontend resolver maps this with robust fallback candidates.
    """
    return "/Assets/product_images/default.jpg"
