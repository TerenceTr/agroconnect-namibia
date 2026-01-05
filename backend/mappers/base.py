# =====================================================================
# backend/mappers/base.py
# ---------------------------------------------------------------------
# ROLE:
#   Base utilities for mapping ORM entities to DTOs.
#
# DESIGN:
#   • Explicit field mapping (no magic)
#   • Type-safe
#   • Testable in isolation
# =====================================================================

from __future__ import annotations
from typing import Any, TypeVar, Callable

T = TypeVar("T")

def require(value: Any, field: str) -> Any:
    """
    Fail fast if a required field is missing.
    Prevents silent corruption in AI pipelines.
    """
    if value is None:
        raise ValueError(f"Required field '{field}' is missing")
    return value


def mapper(fn: Callable[..., T]) -> Callable[..., T]:
    """
    Decorator used to mark mapper functions.
    Helpful for discovery, testing, and documentation.
    """
    return fn
