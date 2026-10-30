"""Scan management endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.rbac import OrgAuthContext, require_role
from app.database import get_db
from app.models.membership import UserRole
from app.models.scan import ScanProfile
from app.schemas.scan import (
    ScanCompareResponse,
    ScanCreateRequest,
    ScanResponse,
)
from app.services.scan_service import ScanService

router = APIRouter(prefix="/organizations/{organization_id}/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
    organization_id: uuid.UUID,
    req: ScanCreateRequest,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> ScanResponse:
    profile = db.get(ScanProfile, req.profile_id)
    if profile and profile.is_intrusive:
        auth_ctx.check_permission(UserRole.ADMIN)
    svc = ScanService(db)
    scan = svc.create_and_enqueue_scan(
        org_id=organization_id,
        auth_id=req.authorization_id,
        profile_id=req.profile_id,
        targets=req.targets,
        intrusive_acknowledged=req.intrusive_acknowledged,
        actor=auth_ctx.user,
    )
    return ScanResponse.model_validate(scan)


@router.get("", response_model=list[ScanResponse])
def list_scans(
    organization_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> list[ScanResponse]:
    svc = ScanService(db)
    scans = svc.list_scans(organization_id, limit=limit, offset=offset)
    return [ScanResponse.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(
    organization_id: uuid.UUID,
    scan_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> ScanResponse:
    svc = ScanService(db)
    scan = svc.get_scan(organization_id, scan_id)
    return ScanResponse.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
def cancel_scan(
    organization_id: uuid.UUID,
    scan_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> ScanResponse:
    svc = ScanService(db)
    scan = svc.cancel_scan(organization_id, scan_id, auth_ctx.user)
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/compare/{compared_scan_id}", response_model=ScanCompareResponse)
def compare_scans(
    organization_id: uuid.UUID,
    scan_id: uuid.UUID,
    compared_scan_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> ScanCompareResponse:
    svc = ScanService(db)
    result = svc.compare_scans(organization_id, scan_id, compared_scan_id)
    return ScanCompareResponse.model_validate(result)
