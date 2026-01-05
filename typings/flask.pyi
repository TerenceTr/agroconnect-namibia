# =====================================================================
# typings/flask.pyi
# Minimal root-module stub for Flask
# =====================================================================

from typing import Any, Callable, Optional, Iterable, Dict

class Response:
    status_code: int
    data: Any
    headers: Dict[str, Any]

def jsonify(*args: Any, **kwargs: Any) -> Response: ...

class Config(dict):
    def from_object(self, obj: Any) -> None: ...
    def get(self, key: str, default: Any = ...) -> Any: ...

class Flask:
    root_path: str
    config: Config

    def __init__(self, import_name: str, static_folder: Optional[str] = None): ...
    def add_url_rule(self, rule: str, endpoint: Optional[str] = ..., view_func: Any = ..., methods: Iterable[str] = ...) -> None: ...
    def errorhandler(self, exc_class: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...
    def register_error_handler(self, exc_class: Any, handler: Callable[..., Any]) -> None: ...
    def app_context(self) -> Any: ...
