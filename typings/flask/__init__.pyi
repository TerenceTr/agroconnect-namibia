# =====================================================================
# typings/flask/__init__.pyi
# ---------------------------------------------------------------------
# Minimal but complete Flask typing stub for Pylance.
#
# Purpose:
#   • Prevent missing attribute errors in backend/app.py
#   • Support:
#       - Flask()
#       - current_app
#       - app.config.get()
#       - app.add_url_rule()
#       - app.errorhandler(), register_error_handler()
#       - jsonify(), Response
#       - AppContext (used in db.create_all)
#       - Route decorators (.get, .post, ...)
#
# NOTE:
#   This is NOT real Flask code — it only provides typing so Pylance
#   stops complaining while you run real Flask in production.
# =====================================================================

from typing import Any, Callable, Iterable, Optional, Dict, Type, Union


# =====================================================================
# Response Object
# =====================================================================
class Response:
    status_code: int
    data: Any
    headers: Dict[str, Any]


# =====================================================================
# jsonify() — returns Response
# =====================================================================
def jsonify(*args: Any, **kwargs: Any) -> Response: ...


# =====================================================================
# Config Object (app.config)
# =====================================================================
class Config(dict):
    def from_object(self, obj: Any) -> None: ...
    def get(self, key: str, default: Any = ...) -> Any: ...


# =====================================================================
# Application Context (supports "with app.app_context():")
# =====================================================================
class AppContext:
    def __enter__(self) -> "AppContext": ...
    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None: ...


# =====================================================================
# Flask Application Class
# =====================================================================
class Flask:
    root_path: str
    config: Config
    static_folder: Optional[str]

    def __init__(self, import_name: str, static_folder: Optional[str] = None): ...

    # Context manager (app.app_context())
    def app_context(self) -> AppContext: ...

    # Register URL rules (used everywhere)
    def add_url_rule(
        self,
        rule: str,
        endpoint: Optional[str] = ...,
        view_func: Callable[..., Any] | None = ...,
        methods: Iterable[str] = ...
    ) -> None: ...

    # Error handlers (used in app.register_error_handler)
    def register_error_handler(self, exc: Any, handler: Callable[..., Any]) -> None: ...
    def errorhandler(self, exc: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...

    # Route decorators
    def get(self, rule: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...
    def post(self, rule: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...
    def put(self, rule: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...
    def delete(self, rule: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...
    def patch(self, rule: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]: ...

    # Run server (development only)
    def run(self, host: str = ..., port: int = ..., debug: bool = ..., **kwargs: Any) -> None: ...


# =====================================================================
# Global current_app proxy — needed for migrations/env.py
# =====================================================================
class _CurrentAppProxy:
    config: Config
    extensions: Dict[str, Any]

current_app: _CurrentAppProxy


# =====================================================================
# send_from_directory (used by your image-serving route)
# =====================================================================
def send_from_directory(directory: str, filename: str, **options: Any) -> Response: ...
