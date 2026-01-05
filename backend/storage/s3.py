# ====================================================================
# backend/storage/s3.py — S3 / MinIO Storage Backend (OPTIONAL-DEP SAFE)
# ====================================================================
# FILE ROLE:
#   • Upload persistence to S3 or MinIO (S3-compatible APIs)
#
# NOTE:
#   This module is imported ONLY when STORAGE_BACKEND=s3
#   (see backend/storage/__init__.py lazy import).
# ====================================================================

from __future__ import annotations

import os
import uuid
from urllib.parse import urljoin

from werkzeug.datastructures import FileStorage

from backend.storage.base import StorageBackend


class S3Storage(StorageBackend):
    """
    S3 / MinIO compatible storage backend.
    """

    def __init__(self) -> None:
        # Import boto3 ONLY when S3Storage is instantiated
        try:
            import boto3  # type: ignore
            from botocore.client import Config  # type: ignore
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "S3Storage requires boto3. Install it or use STORAGE_BACKEND=local."
            ) from exc

        self.bucket = os.environ["STORAGE_BUCKET"]
        self.endpoint = os.getenv("STORAGE_ENDPOINT")
        self.region = os.getenv("STORAGE_REGION", "us-east-1")

        self._boto3 = boto3
        self._Config = Config

        self.client = self._boto3.client(
            "s3",
            region_name=self.region,
            endpoint_url=self.endpoint,
            aws_access_key_id=os.environ["STORAGE_ACCESS_KEY"],
            aws_secret_access_key=os.environ["STORAGE_SECRET_KEY"],
            config=self._Config(signature_version="s3v4"),
        )

    def save(self, file: FileStorage, folder: str) -> str:
        ext = os.path.splitext(file.filename or "")[1]
        key = f"{folder}/{uuid.uuid4().hex}{ext}"

        self.client.upload_fileobj(
            file,
            self.bucket,
            key,
            ExtraArgs={"ACL": "public-read"},
        )

        # Public URL
        if self.endpoint:
            return urljoin(f"{self.endpoint}/", f"{self.bucket}/{key}")

        return f"https://{self.bucket}.s3.{self.region}.amazonaws.com/{key}"

    def generate_signed_url(self, key: str, *, expires: int = 900) -> str:
        return self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires,
        )
