"""Pydantic schemas for Scan, ScanProfile, ScanTarget, and ScanEvent."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.authorization import TargetType
from app.models.scan import ScanStatus


class ScanProfileResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    name: str
    display_name: str
    description: str | None
    requires_confirmation: bool
    is_intrusive: bool
    is_enabled: bool
    config_json: dict

    model_config = ConfigDict(from_attributes=True)


class ScanTargetResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    target_value: str
    target_type: TargetType
    scope_verified: bool

    model_config = ConfigDict(from_attributes=True)


class ScanCreateRequest(BaseModel):
    authorization_id: uuid.UUID
    profile_id: uuid.UUID
    targets: list[str] = Field(..., min_length=1)
    intrusive_acknowledged: bool = False


class ScanResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    authorization_id: uuid.UUID
    profile_id: uuid.UUID
    created_by: uuid.UUID
    status: ScanStatus
    current_stage: str | None
    current_tool: str | None
    current_target: str | None
    progress_pct: int
    error_message: str | None
    findings_count: int
    queued_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    cancelled_at: datetime | None
    timed_out_at: datetime | None
    targets: list[ScanTargetResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class ScanEventResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    event_type: str
    payload: dict
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ScanCompareResponse(BaseModel):
    base_scan_id: uuid.UUID
    compared_scan_id: uuid.UUID
    comparison_note: str
    new_findings_count: int
    resolved_findings_count: int
    persistent_findings_count: int
    new_findings: list[dict] = Field(default_factory=list)
    resolved_findings: list[dict] = Field(default_factory=list)
    persistent_findings: list[dict] = Field(default_factory=list)
