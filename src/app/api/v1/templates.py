from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio.session import AsyncSession

from ...core.db.database import async_get_db
from ...core.auth.auth import get_current_user
from ...models.user_model import UserModel
from ...crud.crud_host_templates import (
    create_host_template,
    get_host_template,
    get_host_template_headers,
)
from ...crud.crud_range_templates import (
    create_range_template,
    get_range_template,
    get_range_template_headers,
)
from ...crud.crud_subnet_templates import (
    create_subnet_template,
    get_subnet_template,
    get_subnet_template_headers,
)
from ...crud.crud_vpc_templates import (
    create_vpc_template,
    get_vpc_template,
    get_vpc_template_headers,
)
from ...schemas.template_host_schema import (
    TemplateHostBaseSchema,
    TemplateHostID,
    TemplateHostSchema,
)
from ...schemas.template_range_schema import (
    TemplateRangeBaseSchema,
    TemplateRangeHeaderSchema,
    TemplateRangeID,
    TemplateRangeSchema,
)
from ...schemas.template_subnet_schema import (
    TemplateSubnetBaseSchema,
    TemplateSubnetHeaderSchema,
    TemplateSubnetID,
    TemplateSubnetSchema,
)
from ...schemas.template_vpc_schema import (
    TemplateVPCBaseSchema,
    TemplateVPCHeaderSchema,
    TemplateVPCID,
    TemplateVPCSchema,
)
from ...validators.id import is_valid_uuid4

router = APIRouter(prefix="/templates", tags=["templates"])


@router.get("/ranges")
async def get_range_template_headers_endpoint(
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user),
) -> list[TemplateRangeHeaderSchema]:
    """Get a list of range template headers.

    Args:
    ----
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        list[TemplateRangeID]: List of range template headers owned by the current user.

    """
    # Get only templates owned by the current user
    range_headers = await get_range_template_headers(db, user_id=current_user.id)

    if not range_headers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Unable to find any range templates that you own!",
        )

    return [
        TemplateRangeHeaderSchema.model_validate(header, from_attributes=True)
        for header in range_headers
    ]


@router.get("/ranges/{range_id}")
async def get_range_template_endpoint(
    range_id: str, 
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> TemplateRangeSchema:
    """Get a range template.

    Args:
    ----
        range_id (str): ID of the range.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        TemplateRangeSchema: Range template data from database if it belongs to the user.

    """
    if not is_valid_uuid4(range_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID provided is not a valid UUID4.",
        )

    # Get the template and check if the user is the owner
    range_template = await get_range_template(
        db, 
        TemplateRangeID(id=range_id), 
        user_id=current_user.id
    )

    if not range_template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Range with id: {range_id} not found or you don't have access to it!",
        )

    return TemplateRangeSchema.model_validate(range_template, from_attributes=True)


@router.post("/ranges")
async def upload_range_template_endpoint(
    range_template: TemplateRangeBaseSchema,
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> TemplateRangeID:
    """Upload a range template.

    Args:
    ----
        range_template (TemplateRangeBaseSchema): OpenLabs compliant range template object.
        db (AsynSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        TemplateRangeID: Identity of the range template.

    """
    created_range = await create_range_template(db, range_template, current_user.id)
    return TemplateRangeID.model_validate(created_range, from_attributes=True)


@router.get("/vpcs")
async def get_vpc_template_headers_endpoint(
    standalone_only: bool = True,
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user),
) -> list[TemplateVPCHeaderSchema]:
    """Get a list of vpc template headers.

    Args:
    ----
        standalone_only (bool): Return only standalone VPC templates (not part of a range template). Defaults to True.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        list[TemplateVPCID]: List of vpc template headers owned by the current user.

    """
    # Get only templates owned by the current user
    vpc_headers = await get_vpc_template_headers(
        db, 
        user_id=current_user.id, 
        standalone_only=standalone_only
    )

    if not vpc_headers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unable to find any{" standalone" if standalone_only else ""} vpc templates that you own!",
        )

    return [
        TemplateVPCHeaderSchema.model_validate(header, from_attributes=True)
        for header in vpc_headers
    ]


@router.get("/vpcs/{vpc_id}")
async def get_vpc_template_endpoint(
    vpc_id: str, 
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> TemplateVPCSchema:
    """Get a VPC template.

    Args:
    ----
        vpc_id (str): ID of the VPC template.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        TemplateVPCSchema: Template VPC data from database if it belongs to the user.

    """
    if not is_valid_uuid4(vpc_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID provided is not a valid UUID4.",
        )

    # Get the template and check if the user is the owner
    vpc_template = await get_vpc_template(
        db, 
        TemplateVPCID(id=vpc_id), 
        user_id=current_user.id
    )

    if not vpc_template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"VPC with id: {vpc_id} not found or you don't have access to it!",
        )

    return TemplateVPCSchema.model_validate(vpc_template, from_attributes=True)


@router.post("/vpcs")
async def upload_vpc_template_endpoint(
    vpc_template: TemplateVPCBaseSchema,
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> TemplateVPCID:
    """Upload a VPC template.

    Args:
    ----
        vpc_template (TemplateVPCBaseSchema): OpenLabs compliant VPC object.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        TemplateVPCID: Identity of the VPC template.

    """
    # Create the template with the current user as the owner
    created_vpc = await create_vpc_template(
        db, 
        vpc_template, 
        owner_id=current_user.id
    )
    return TemplateVPCID.model_validate(created_vpc, from_attributes=True)


@router.get("/subnets")
async def get_subnet_template_headers_endpoint(
    standalone_only: bool = True,
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user),
) -> list[TemplateSubnetHeaderSchema]:
    """Get a list of subnet template headers.

    Args:
    ----
        standalone_only (bool): Return only standalone subnet templates (not part of a range/vpc template). Defaults to True.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        list[TemplateSubnetHeaderSchema]: List of subnet template headers owned by the current user.

    """
    # Get subnet headers filtered by owner_id
    subnet_headers = await get_subnet_template_headers(
        db, standalone_only=standalone_only, user_id=current_user.id
    )

    if not subnet_headers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unable to find any{" standalone" if standalone_only else ""} subnet templates that you own!",
        )

    return [
        TemplateSubnetHeaderSchema.model_validate(header, from_attributes=True)
        for header in subnet_headers
    ]


@router.get("/subnets/{subnet_id}")
async def get_subnet_template_endpoint(
    subnet_id: str, 
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> TemplateSubnetSchema:
    """Get a subnet template.

    Args:
    ----
        subnet_id (str): ID of the subnet.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        TemplateSubnetSchema: Subnet data from database if it belongs to the user.

    """
    if not is_valid_uuid4(subnet_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID provided is not a valid UUID4.",
        )

    subnet_template = await get_subnet_template(db, TemplateSubnetID(id=subnet_id), user_id=current_user.id)

    if not subnet_template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Subnet with id: {subnet_id} not found or you don't have access to it!",
        )

    return TemplateSubnetSchema.model_validate(subnet_template, from_attributes=True)


@router.post("/subnets")
async def upload_subnet_template_endpoint(
    subnet_template: TemplateSubnetBaseSchema,
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> TemplateSubnetID:
    """Upload a subnet template.

    Args:
    ----
        subnet_template (TemplateSubnetBaseSchema): OpenLabs compliant subnet template object.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        TemplateSubnetID: Identity of the subnet template.

    """
    # Create subnet with current user as owner
    created_subnet = await create_subnet_template(
        db, 
        subnet_template,
        owner_id=current_user.id
    )
    
    return TemplateSubnetID.model_validate(created_subnet, from_attributes=True)


@router.get("/hosts")
async def get_host_template_headers_endpoint(
    standalone_only: bool = True,
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> list[TemplateHostSchema]:
    """Get a list of host template headers.

    Args:
    ----
        standalone_only (bool): Return only standalone host templates (not part of a range/vpc/subnet template). Defaults to True.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        list[TemplateHostID]: List of host template UUIDs owned by the current user.

    """
    # Get host headers filtered by owner_id
    host_headers = await get_host_template_headers(
        db, standalone_only=standalone_only, user_id=current_user.id
    )

    if not host_headers:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unable to find any{" standalone" if standalone_only else ""} host templates that you own!",
        )

    return [
        TemplateHostSchema.model_validate(header, from_attributes=True)
        for header in host_headers
    ]


@router.get("/hosts/{host_id}")
async def get_host_template_endpoint(
    host_id: str, 
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> TemplateHostSchema:
    """Get a host template.

    Args:
    ----
        host_id (str): Id of the host.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        TemplateHostSchema: Host data from database if it belongs to the user.

    """
    if not is_valid_uuid4(host_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="ID provided is not a valid UUID4.",
        )

    host_template = await get_host_template(db, TemplateHostID(id=host_id), user_id=current_user.id)

    if not host_template:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Host with id: {host_id} not found or you don't have access to it!",
        )

    return TemplateHostSchema.model_validate(host_template, from_attributes=True)


@router.post("/hosts")
async def upload_host_template_endpoint(
    host_template: TemplateHostBaseSchema,
    db: AsyncSession = Depends(async_get_db),  # noqa: B008
    current_user: UserModel = Depends(get_current_user)
) -> TemplateHostID:
    """Upload a host template.

    Args:
    ----
        host_template (TemplateHostBaseSchema): OpenLabs compliant host template object.
        db (AsyncSession): Async database connection.
        current_user (UserModel): Currently authenticated user.

    Returns:
    -------
        TemplateHostID: Identity of the host template.

    """
    # Create host with current user as owner
    created_host = await create_host_template(
        db, 
        host_template,
        owner_id=current_user.id
    )
    
    return TemplateHostID.model_validate(created_host, from_attributes=True)
