"""Finding endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.core.rbac import OrgAuthContext, require_role
from app.database import get_db
from app.models.finding import Finding, FindingConfidence, FindingSeverity, FindingStatus
from app.models.membership import UserRole
from app.schemas.finding import (
    FindingAssignRequest,
    FindingResponse,
    FindingStatusUpdate,
    FindingSummaryResponse,
    RemediationNoteCreate,
    RemediationNoteResponse,
)
from app.schemas.remediation import RemediationSchema
from app.services.finding_service import FindingService
from app.services.remediation_service import RemediationService

router = APIRouter(prefix="/organizations/{organization_id}/findings", tags=["Findings"])

# Evidence rows returned by the detail view (newest first); a finding seen by
# many scans accumulates one row per sighting.
MAX_DETAIL_EVIDENCE = 50


def finding_detail(finding: Finding) -> FindingResponse:
    """Detail response: newest evidence first (at most MAX_DETAIL_EVIDENCE), newest notes first."""
    response = FindingResponse.model_validate(finding)
    newest_first = sorted(response.evidence, key=lambda item: item.collected_at, reverse=True)
    response.evidence = newest_first[:MAX_DETAIL_EVIDENCE]
    response.remediation_notes = sorted(
        response.remediation_notes, key=lambda item: item.created_at, reverse=True
    )
    return response


@router.get("", response_model=list[FindingSummaryResponse])
def list_findings(
    organization_id: uuid.UUID,
    severity: FindingSeverity | None = None,
    status: FindingStatus | None = None,
    confidence: FindingConfidence | None = None,
    source_tool: str | None = None,
    asset_id: uuid.UUID | None = None,
    search: str | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> list[FindingSummaryResponse]:
    svc = FindingService(db)
    findings = svc.list_findings(
        org_id=organization_id,
        severity=severity,
        status=status,
        confidence=confidence,
        source_tool=source_tool,
        asset_id=asset_id,
        search=search,
        limit=limit,
        offset=offset,
    )
    return [FindingSummaryResponse.model_validate(f) for f in findings]


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> FindingResponse:
    svc = FindingService(db)
    finding = svc.get_finding(organization_id, finding_id)
    return finding_detail(finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
def update_finding_status(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    req: FindingStatusUpdate,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> FindingResponse:
    svc = FindingService(db)
    finding = svc.update_status(
        org_id=organization_id,
        finding_id=finding_id,
        new_status=req.status,
        actor=auth_ctx.user,
        accepted_risk_reason=req.accepted_risk_reason,
    )
    return finding_detail(finding)


@router.post("/{finding_id}/assign", response_model=FindingResponse)
def assign_finding(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    req: FindingAssignRequest,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> FindingResponse:
    svc = FindingService(db)
    finding = svc.assign_finding(
        org_id=organization_id,
        finding_id=finding_id,
        target_user_id=req.user_id,
        actor=auth_ctx.user,
    )
    return finding_detail(finding)


@router.post(
    "/{finding_id}/notes",
    response_model=RemediationNoteResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_note(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    req: RemediationNoteCreate,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> RemediationNoteResponse:
    svc = FindingService(db)
    note = svc.add_note(
        org_id=organization_id,
        finding_id=finding_id,
        note_text=req.note,
        actor=auth_ctx.user,
    )
    return RemediationNoteResponse.model_validate(note)


@router.get("/{finding_id}/notes", response_model=list[RemediationNoteResponse])
def list_notes(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.VIEWER)),
    db: Session = Depends(get_db),
) -> list[RemediationNoteResponse]:
    svc = FindingService(db)
    notes = svc.list_notes(organization_id, finding_id)
    return [RemediationNoteResponse.model_validate(n) for n in notes]


@router.post("/{finding_id}/remediation", response_model=RemediationSchema)
def trigger_remediation(
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    force_refresh: bool = False,
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ANALYST)),
    db: Session = Depends(get_db),
) -> RemediationSchema:
    svc = RemediationService(db)
    remediation = svc.get_or_generate_remediation(
        org_id=organization_id,
        finding_id=finding_id,
        actor=auth_ctx.user,
        force_refresh=force_refresh,
    )
    return remediation
