import uuid

from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, MappedAsDataclass, mapped_column


class OpenLabsTemplateMixin(MappedAsDataclass):
    """Mixin to provide a UUID for each template-based model."""

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )

class OpenLabsUserMixin(MappedAsDataclass):
    """Mixin to provide a UUID for each user-based model."""

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
    )
