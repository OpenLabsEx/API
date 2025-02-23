import uuid
iport datetime

from pydantic import BaseModel, Field, field_validator, ConfigDict
from email_validator import validate_email, EmailNotValidError

class UserBaseSchema(BaseModel):
    """Schema for user authentication."""

    email: str = Field(
        ...,
        description="Email of user",
        min_length=1,
        examples=["adam@ufsit.club", "alex@christy.com", "naresh@panch.al"],
    )

    password: str = Field(
        ...,
        description = "Password of user",
        min_length = 1,
        examples=["password123"]
    )

    @field_validator("email")
    @classmethod
    def validate_email(
        cls, email: str) -> str:
        """Check that email format is valid.
        Args:
        ----
            cls: OpenLabsUser object.
            email (str): User email address.
        Returns:
        -------
            str: User email address.
        """

        try:
            emailinfo = validate_email(email, check_deliverability=False)

            return emailinfo.normalized
        except EmailNotValidError:
            msg = "Provided email address is invalid."
            raise ValueError(msg)

class UserCreateBaseSchema(UserBaseSchema):
    """User object for user creation in OpenLabs."""

    name: str = Field(
        ...,
        description="Full name of user",
        min_length=1,
        examples=["Adam Hassan", "Alex Christy", "Naresh Panchal"]
    )

    @field_validator("email")
    @classmethod
    def validate_email(
        cls, email: str) -> str:
        """Check that email format is valid.
        Args:
        ----
            cls: OpenLabsUser object.
            email (str): User email address.
        Returns:
        -------
            str: User email address.
        """

        try:
            # Makes a DNS query to validate deliverability
            # We do this, as users will only be added to DB on registration
            emailinfo = validate_email(email, check_deliverability=True)

            return emailinfo.normalized
        except EmailNotValidError:
            msg = "Provided email address is invalid."
            raise ValueError(msg)


class UserID(BaseModel):
    """Identity class for UserCreate."""

    id: uuid.UUID = Field(
        default_factory=uuid.uuid4, description="Unique user identifier."
    )

    model_config = ConfigDict(from_attributes=True)

class UserCreateSchema(UserCreateBaseSchema, UserID):
    """User creation object for OpenLabs."""

    model_config = ConfigDict(from_attributes=True)
