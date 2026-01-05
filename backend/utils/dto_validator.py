# =====================================================================
# backend/utils/dto_validator.py
# ---------------------------------------------------------------------
# ROLE:
#   Validate DTOs before sending them outside the API boundary.
#
# WHY:
#   • Prevent corrupted AI input
#   • Catch missing fields early
#   • Make failures loud and explicit
# =====================================================================

from dataclasses import fields, is_dataclass


def validate_dto(dto: object) -> None:
    if not is_dataclass(dto):
        raise TypeError("Expected a dataclass DTO")

    for f in fields(dto):
        value = getattr(dto, f.name)
        if value is None and f.default is f.default_factory:
            raise ValueError(f"DTO field '{f.name}' is required but None")
