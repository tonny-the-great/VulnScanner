"""Pydantic schemas for organizations and memberships."""

from __future__ import annotations

import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.membership import UserRole


class OrganizationBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    slug: str = Field(..., min_length=3, max_length=100)

    @field_validator("slug")
    @classmethod
    def validate_slug(cls, v: str) -> str:
        clean = v.strip().lower()
        if not re.match(r"^[a-z0-9][a-z0-9\-]{1,98}[a-z0-9]$", clean):
            raise ValueError("Slug must contain only lowercase alphanumeric characters and hyphens")
        return clean


def _clean_organization_name(value: str) -> str:
    clean = value.strip()
    if len(clean) < 2:
        raise ValueError("Organization name must contain at least 2 non-space characters")
    return clean


class OrganizationCreate(OrganizationBase):
    max_concurrent_scans: int = Field(default=2, ge=1, le=10)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        return _clean_organization_name(v)


class OrganizationUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=255)
    max_concurrent_scans: int | None = Field(default=None, ge=1, le=10)
    is_active: bool | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        return None if v is None else _clean_organization_name(v)


class OrganizationResponse(OrganizationBase):
    id: uuid.UUID
    is_active: bool
    max_concurrent_scans: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class MemberAddRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    role: UserRole = Field(default=UserRole.ANALYST)


class MemberRoleUpdate(BaseModel):
    role: UserRole


class MemberResponse(BaseModel):
    id: uuid.UUID
    user_id: uuid.UUID
    organization_id: uuid.UUID
    email: str
    full_name: str
    role: UserRole
    joined_at: datetime

    model_config = ConfigDict(from_attributes=True)
