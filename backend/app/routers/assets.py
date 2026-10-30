"""Asset endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.rbac import OrgAuthContext, require_role
from app.database import get_db
from app.models.membership import UserRole
from app.schemas.asset import AssetResponse, AssetUpdate
from app.schemas.finding import FindingSummaryResponse
from app.services.asset_service import AssetService

router = APIRouter(prefix="/organizations/{organization_id}/assets", tags=["Assets"])


@router.get("", response_model=list[AssetResponse])
def list_assets(
    organization_id: uuid.UUID,
    is_active: bool | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> list[AssetResponse]:
    svc = AssetService(db)
    assets = svc.list_assets(organization_id, limit=limit, offset=offset, is_active=is_active)
    return [AssetResponse.model_validate(a) for a in assets]


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> AssetResponse:
    svc = AssetService(db)
    asset = svc.get_asset(organization_id, asset_id)
    return AssetResponse.model_validate(asset)


@router.get("/{asset_id}/findings", response_model=list[FindingSummaryResponse])
def get_asset_findings(
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> list[FindingSummaryResponse]:
    svc = AssetService(db)
    findings = svc.get_asset_findings(organization_id, asset_id, limit=limit, offset=offset)
    return [FindingSummaryResponse.model_validate(f) for f in findings]


@router.patch("/{asset_id}", response_model=AssetResponse)
def update_asset(
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    req: AssetUpdate,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> AssetResponse:
    svc = AssetService(db)
    asset = svc.update_asset(
        org_id=organization_id,
        asset_id=asset_id,
        actor=auth_ctx.user,
        notes=req.notes,
        is_active=req.is_active,
    )
    return AssetResponse.model_validate(asset)
