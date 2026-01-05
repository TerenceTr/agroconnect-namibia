# typings\werkzeug\exceptions.pyi
from typing import Any, Optional

class HTTPException(Exception):
    description: str
    code: int
    def __init__(self, *args: Any, **kwargs: Any) -> None: ...
