"""Pydantic schemas for Audit Log."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class AuditLogResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    actor_id: uuid.UUID | None
    actor_email: str | None
    ip_address: str | None
    action: str
    resource_type: str
    resource_id: str | None
    metadata_sanitized: dict = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
