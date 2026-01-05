from typing import Any
from flask import Response

def send_from_directory(directory: str, filename: str, **options: Any) -> Response: ...
