"""Organizations and memberships endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.core.rbac import OrgAuthContext, require_role
from app.core.security import get_current_user
from app.database import get_db
from app.models.membership import UserRole
from app.models.user import User
from app.schemas.organization import (
    MemberAddRequest,
    MemberResponse,
    MemberRoleUpdate,
    OrganizationCreate,
    OrganizationResponse,
    OrganizationUpdate,
)
from app.services.organization_service import OrganizationService

router = APIRouter(prefix="/organizations", tags=["Organizations"])


@router.post("", response_model=OrganizationResponse, status_code=status.HTTP_201_CREATED)
def create_organization(
    req: OrganizationCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    svc = OrganizationService(db)
    org = svc.create_organization(
        name=req.name,
        slug=req.slug,
        actor=user,
        max_concurrent_scans=req.max_concurrent_scans,
    )
    return OrganizationResponse.model_validate(org)


@router.get("", response_model=list[OrganizationResponse])
def list_organizations(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[OrganizationResponse]:
    svc = OrganizationService(db)
    orgs = svc.list_user_organizations(user)
    return [OrganizationResponse.model_validate(o) for o in orgs]


@router.get("/{organization_id}", response_model=OrganizationResponse)
def get_organization(
    organization_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    svc = OrganizationService(db)
    org = svc.get_organization(organization_id)
    return OrganizationResponse.model_validate(org)


@router.patch("/{organization_id}", response_model=OrganizationResponse)
def update_organization(
    organization_id: uuid.UUID,
    req: OrganizationUpdate,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> OrganizationResponse:
    svc = OrganizationService(db)
    org = svc.update_organization(
        org_id=organization_id,
        name=req.name,
        max_concurrent_scans=req.max_concurrent_scans,
        is_active=req.is_active,
        actor=auth_ctx.user,
    )
    return OrganizationResponse.model_validate(org)


@router.get("/{organization_id}/members", response_model=list[MemberResponse])
def list_members(
    organization_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> list[MemberResponse]:
    svc = OrganizationService(db)
    members = svc.list_members(organization_id)
    return [MemberResponse.model_validate(m) for m in members]


@router.post(
    "/{organization_id}/members", response_model=MemberResponse, status_code=status.HTTP_201_CREATED
)
def add_member(
    organization_id: uuid.UUID,
    req: MemberAddRequest,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> MemberResponse:
    svc = OrganizationService(db)
    member = svc.add_member(
        org_id=organization_id,
        email=req.email,
        role=req.role,
        actor=auth_ctx.user,
    )
    return MemberResponse.model_validate(member)


@router.patch("/{organization_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def update_member_role(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    req: MemberRoleUpdate,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> None:
    svc = OrganizationService(db)
    svc.update_member_role(
        org_id=organization_id,
        target_user_id=user_id,
        new_role=req.role,
        actor=auth_ctx.user,
    )


@router.delete("/{organization_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> None:
    svc = OrganizationService(db)
    svc.remove_member(
        org_id=organization_id,
        target_user_id=user_id,
        actor=auth_ctx.user,
    )
