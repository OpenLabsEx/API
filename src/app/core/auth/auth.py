from datetime import UTC, datetime

import jwt
from fastapi import Cookie, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from ...crud.crud_users import get_user_by_id
from ...models.user_model import UserModel
from ...schemas.user_schema import UserID
from ..config import settings
from ..db.database import async_get_db

# Create a security scheme using HTTPBearer (kept for backward compatibility)
security = HTTPBearer(auto_error=False)


async def get_current_user(
    request: Request,
    token: str | None = Cookie(None, alias="token", include_in_schema=False),
    credentials: HTTPAuthorizationCredentials | None = Depends(security),  # noqa: B008
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
) -> UserModel:
    """Get the current user from the JWT token.

    Args:
    ----
        request (Request): The FastAPI request object
        token (Optional[str]): HTTP-only cookie containing JWT
        credentials (Optional[HTTPAuthorizationCredentials]): HTTP Bearer token (fallback)
        db (AsyncSession): Database connection

    Returns:
    -------
        UserModel: The current authenticated user

    Raises:
    ------
        ValueError: If the token is invalid or the user doesn't exist

    """
    jwt_token = None
    # First, try to get the token from the cookie
    if token:
        jwt_token = token
    # If no cookie, try to get from Authorization header (backward compatibility)
    elif credentials and credentials.credentials:
        jwt_token = credentials.credentials
    # If neither is present, raise an exception
    else:
        msg = "auth:missing_credentials:Authentication credentials missing"
        raise ValueError(msg)
    try:
        # Decode the JWT token
        payload = jwt.decode(
            jwt_token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
        )

        # Get the user ID from the token
        user_id = payload.get("user")

        if user_id is None:
            msg = "auth:invalid_credentials:Invalid authentication credentials"
            raise ValueError(msg)

        # Get the expiration time from the token
        expiration = payload.get("exp")
        if expiration is None:
            msg = "auth:no_expiration:Token has no expiration"
            raise ValueError(msg)

        # Check if the token has expired
        if datetime.now(UTC) > datetime.fromtimestamp(expiration, tz=UTC):
            msg = "auth:expired:Token has expired"
            raise ValueError(msg)

        # Get the user from the database
        user = await get_user_by_id(db, UserID(id=user_id))
        if user is None:
            msg = "auth:user_not_found:User not found"
            raise ValueError(msg)

        # Update the last_active field - remove timezone to match DB schema
        now = datetime.now(UTC)
        user.last_active = now.replace(tzinfo=None)
        await db.commit()

        return user

    except jwt.PyJWTError as e:
        msg = "auth:invalid_token:Invalid authentication credentials"
        raise ValueError(msg) from e


def is_admin(user: UserModel = Depends(get_current_user)) -> UserModel:  # noqa: B008
    """Check if the user is an admin.

    Args:
    ----
        user (UserModel): The authenticated user

    Returns:
    -------
        UserModel: The authenticated user if they are an admin

    Raises:
    ------
        ValueError: If the user is not an admin

    """
    if not user.is_admin:
        msg = "auth:forbidden:Not enough permissions"
        raise ValueError(msg)
    return user
