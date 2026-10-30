"""Pydantic schemas for Reports."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.report import ReportType


class ReportCreateRequest(BaseModel):
    scan_id: uuid.UUID | None = None
    report_type: ReportType = ReportType.EXECUTIVE
    title: str = Field(..., min_length=3, max_length=512)


class ReportResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    scan_id: uuid.UUID | None
    report_type: ReportType
    title: str
    generated_by: uuid.UUID
    generated_at: datetime
    access_token: str
    token_expires_at: datetime

    model_config = ConfigDict(from_attributes=True)
