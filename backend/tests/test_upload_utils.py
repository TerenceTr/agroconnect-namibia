# backend/tests/test_upload_utils.py
import io
import pytest
from werkzeug.datastructures import FileStorage

from backend.utils.upload_utils import save_image


def make_image(name="test.jpg", size=1024):
    return FileStorage(
        stream=io.BytesIO(b"x" * size),
        filename=name,
        content_type="image/jpeg",
    )


def test_save_image_success(app):
    with app.app_context():
        img = make_image()
        url = save_image(img, folder="test")

        assert url is not None
        assert url.startswith("/uploads/test/")
        assert url.endswith(".jpg")


def test_save_image_invalid_extension(app):
    with app.app_context():
        img = make_image(name="bad.txt")

        with pytest.raises(ValueError):
            save_image(img)


def test_save_image_too_large(app):
    with app.app_context():
        img = make_image(size=6 * 1024 * 1024)

        with pytest.raises(ValueError):
            save_image(img)
