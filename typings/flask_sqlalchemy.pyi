# =====================================================================
# typings/flask_sqlalchemy.pyi
# ---------------------------------------------------------------------
# SQLAlchemy typing stub for Flask-SQLAlchemy
# Fully fixes:
#   • db.Column(...) callable
#   • db.String, db.Text, db.DateTime callable
#   • db.ForeignKey
#   • db.Model inheritance
#   • db.metadata (Alembic)
#   • db.Uuid
# =====================================================================

from typing import Any, Optional


# =====================================================================
# Base Declarative Model Stub
# =====================================================================
class Model:
    """Base placeholder for SQLAlchemy declarative models."""
    pass


# =====================================================================
# Primitive SQLAlchemy Type Stubs
# =====================================================================
class Column:
    def __init__(self, *args: Any, **kwargs: Any): ...


class Integer: ...
class String:
    def __init__(self, length: int = ...): ...
class Text: ...
class Boolean: ...
class Float: ...
class JSON: ...
class LargeBinary: ...
class Numeric:
    def __init__(self, precision: int = ..., scale: int = ...): ...
class DateTime:
    def __init__(self, timezone: Optional[bool] = ...): ...
class Uuid: ...
class ForeignKey:
    def __init__(self, target: str, ondelete: Optional[str] = None): ...


# =====================================================================
# SQLAlchemy Main Object Stub
# =====================================================================
class SQLAlchemy:
    """SQLAlchemy() object used as: db = SQLAlchemy()"""

    # Flask-SQLAlchemy core attributes
    Model: type[Model]       # Model class
    session: Any
    engine: Any
    metadata: Any            # Required by Alembic

    # Column and types — factories MUST be callable (use type[])
    Column: type[Column]
    Integer: type[Integer]
    String: type[String]
    Text: type[Text]
    Boolean: type[Boolean]
    Float: type[Float]
    JSON: type[JSON]
    LargeBinary: type[LargeBinary]
    Numeric: type[Numeric]
    DateTime: type[DateTime]
    ForeignKey: type[ForeignKey]
    Uuid: type[Uuid]         # Used in your models

    def __init__(self, *args: Any, **kwargs: Any): ...
    def init_app(self, app: Any) -> None: ...

    # Common helper methods
    def create_all(self) -> None: ...
    def drop_all(self) -> None: ...
    def reflect(self) -> None: ...
    def get_engine(self, app: Any = ...) -> Any: ...
