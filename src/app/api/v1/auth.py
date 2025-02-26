from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from bcrypt import checkpw
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio.session import AsyncSession

from ...core.config import settings
from ...core.db.database import async_get_db
from ...crud.crud_users import create_user, get_user
from ...schemas.user_schema import (
    UserBaseSchema,
    UserCreateBaseSchema,
    UserID,
)

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/login")
async def login(
    openlabs_user: UserBaseSchema,
    db: AsyncSession = Depends(async_get_db), # noqa: B008
) -> dict[str, str]:
    """Login a user.

    Args:
    ----
        openlabs_user (UserBaseSchema): User authentication data.
        db (AsyncSession): Async database connection.

    Returns:
    -------
        dict: token with JWT for the user.

    """
    user = await get_user(db, openlabs_user.email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or user does not exist",
        )

    user_hash = user.hashed_password
    user_id = user.id

    if not checkpw(openlabs_user.password.encode(), user_hash.encode()):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials or user does not exist",
        )


    data_dict: dict[str, Any] = {
        "user": str(user_id)
    }

    expire = datetime.now(UTC) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)


    data_dict.update({"exp": expire})

    return {
        "token": jwt.encode(data_dict, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    }


@router.post("/register")
async def register_new_user(
    openlabs_user: UserCreateBaseSchema,
    db: AsyncSession = Depends(async_get_db), # noqa: B008
) -> UserID:
    """Create a new user.

    Args:
    ----
        openlabs_user (UserCreateBaseSchema): User creation data.
        db (AsyncSession): Async database connection.

    Returns:
    -------
        UserID: Identity of the created user.

    """
    existing_user = await get_user(db, openlabs_user.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists",
        )
    created_user = await create_user(db, openlabs_user)

    if not created_user:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Unable to create user",
        )

    return UserID.model_validate(created_user, from_attributes=True)
