"""Pydantic schemas for Findings, Evidence, Notes, and Assignments."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import FindingConfidence, FindingSeverity, FindingStatus


class FindingEvidenceResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    scan_id: uuid.UUID
    evidence_type: str
    content: str
    collected_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RemediationNoteCreate(BaseModel):
    note: str = Field(..., min_length=1, max_length=5000)


class RemediationNoteResponse(BaseModel):
    id: uuid.UUID
    finding_id: uuid.UUID
    author_id: uuid.UUID
    note: str
    status_at_time: FindingStatus
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingStatusUpdate(BaseModel):
    status: FindingStatus
    # Only used when status is accepted_risk; ignored for every other status.
    accepted_risk_reason: str | None = Field(default=None, max_length=5000)


class FindingAssignRequest(BaseModel):
    user_id: uuid.UUID


class FindingSummaryResponse(BaseModel):
    """
    A finding without its evidence and notes, for list views.

    Evidence holds raw scanner output and can be large; it is only returned by
    the finding detail endpoint (FindingResponse).
    """

    id: uuid.UUID
    organization_id: uuid.UUID
    asset_id: uuid.UUID | None
    service_id: uuid.UUID | None
    title: str
    description: str | None
    source_tool: str
    scanner_reference: str | None
    confidence: FindingConfidence
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    severity: FindingSeverity
    cvss_score: float | None
    cvss_vector: str | None
    priority_score: float | None
    fingerprint: str
    status: FindingStatus
    assigned_to: uuid.UUID | None
    first_seen: datetime
    last_seen: datetime
    fixed_at: datetime | None
    accepted_risk_at: datetime | None
    accepted_risk_reason: str | None
    first_seen_scan_id: uuid.UUID | None
    last_seen_scan_id: uuid.UUID | None
    llm_remediation: dict | None
    llm_remediation_cached_at: datetime | None
    llm_remediation_failed: bool

    model_config = ConfigDict(from_attributes=True)


class FindingResponse(FindingSummaryResponse):
    """A single finding with its evidence and remediation notes (detail view)."""

    evidence: list[FindingEvidenceResponse] = Field(default_factory=list)
    remediation_notes: list[RemediationNoteResponse] = Field(default_factory=list)
