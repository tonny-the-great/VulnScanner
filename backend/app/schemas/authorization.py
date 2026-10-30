"""Pydantic schemas for ScopeAuthorization and AuthorizedTarget."""

from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.authorization import TargetType


class AuthorizedTargetCreate(BaseModel):
    value: str = Field(..., min_length=1, max_length=512)
    notes: str | None = Field(default=None, max_length=500)


class AuthorizedTargetResponse(BaseModel):
    id: uuid.UUID
    authorization_id: uuid.UUID
    target_type: TargetType
    value: str
    notes: str | None

    model_config = ConfigDict(from_attributes=True)


class ScopeAuthorizationCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    signer_name: str = Field(..., min_length=2, max_length=255)
    signer_email: EmailStr
    authorization_date: date
    expiration_date: date | None = None
    notes: str | None = None
    targets: list[AuthorizedTargetCreate] = Field(default_factory=list)


class ScopeAuthorizationUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    expiration_date: date | None = None
    notes: str | None = None


class ScopeAuthorizationResponse(BaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    signer_name: str
    signer_email: str
    authorization_date: date
    expiration_date: date | None
    document_path: str | None
    notes: str | None
    is_revoked: bool
    revoked_at: datetime | None
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime
    is_valid: bool
    authorized_targets: list[AuthorizedTargetResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)
