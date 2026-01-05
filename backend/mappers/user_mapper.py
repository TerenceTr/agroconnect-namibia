# =====================================================================
# backend/mappers/user_mapper.py
# =====================================================================

from backend.dto.user_dto import UserDTO
from backend.models.user import User
from backend.mappers.base import mapper, require


@mapper
def user_to_dto(user: User) -> UserDTO:
    return UserDTO(
        id=require(user.id, "id"),
        full_name=require(user.full_name, "full_name"),
        role=require(user.role, "role"),
        location=user.location,
    )
