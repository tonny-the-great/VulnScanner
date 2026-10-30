"""Pydantic schemas for Assets and Services."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.models.asset import AssetType, ServiceProtocol, ServiceState


class ServiceResponse(BaseModel):
    id: uuid.UUID
    asset_id: uuid.UUID
    protocol: ServiceProtocol
    port: int
    service_name: str | None
    product: str | None
    version: str | None
    extra_info: str | None
    state: ServiceState
    first_seen: datetime
    last_seen: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    asset_type: AssetType
    ip_address: str | None
    hostname: str | None
    domain: str | None
    os_name: str | None
    os_version: str | None
    os_confidence: int | None
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    discovery_source: str
    notes: str | None
    services: list[ServiceResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class AssetUpdate(BaseModel):
    # None leaves a field unchanged; an empty string clears the notes.
    notes: str | None = Field(default=None, max_length=5000)
    is_active: bool | None = None
