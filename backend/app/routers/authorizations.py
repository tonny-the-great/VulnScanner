"""Scope authorization management endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.rbac import OrgAuthContext, require_role
from app.database import get_db
from app.models.membership import UserRole
from app.schemas.authorization import (
    ScopeAuthorizationCreate,
    ScopeAuthorizationResponse,
)
from app.services.authorization_service import AuthorizationService

router = APIRouter(
    prefix="/organizations/{organization_id}/authorizations", tags=["Scope Authorizations"]
)


@router.post("", response_model=ScopeAuthorizationResponse, status_code=status.HTTP_201_CREATED)
def create_authorization(
    organization_id: uuid.UUID,
    req: ScopeAuthorizationCreate,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> ScopeAuthorizationResponse:
    svc = AuthorizationService(db)
    targets_data = [{"value": t.value, "notes": t.notes} for t in req.targets]
    auth = svc.create_authorization(
        org_id=organization_id,
        title=req.title,
        signer_name=req.signer_name,
        signer_email=req.signer_email,
        authorization_date=req.authorization_date,
        expiration_date=req.expiration_date,
        notes=req.notes,
        targets=targets_data,
        actor=auth_ctx.user,
    )
    return ScopeAuthorizationResponse.model_validate(auth)


@router.get("", response_model=list[ScopeAuthorizationResponse])
def list_authorizations(
    organization_id: uuid.UUID,
    limit: int = Query(default=100, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> list[ScopeAuthorizationResponse]:
    svc = AuthorizationService(db)
    authorizations = svc.list_authorizations(organization_id, limit=limit, offset=offset)
    return [ScopeAuthorizationResponse.model_validate(a) for a in authorizations]


@router.get("/{authorization_id}", response_model=ScopeAuthorizationResponse)
def get_authorization(
    organization_id: uuid.UUID,
    authorization_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> ScopeAuthorizationResponse:
    svc = AuthorizationService(db)
    auth = svc.get_authorization(organization_id, authorization_id)
    return ScopeAuthorizationResponse.model_validate(auth)


@router.delete("/{authorization_id}", response_model=ScopeAuthorizationResponse)
def revoke_authorization(
    organization_id: uuid.UUID,
    authorization_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> ScopeAuthorizationResponse:
    svc = AuthorizationService(db)
    auth = svc.revoke_authorization(organization_id, authorization_id, auth_ctx.user)
    return ScopeAuthorizationResponse.model_validate(auth)
