"""Pydantic schemas for auth endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.core.password_policy import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    validate_password_policy,
)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=1, max_length=PASSWORD_MAX_LENGTH)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    full_name: str = Field(..., min_length=2, max_length=255)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: str) -> str:
        return v.lower().strip()

    @model_validator(mode="after")
    def check_password_policy(self) -> RegisterRequest:
        # A ValueError here becomes a 422 response listing every problem.
        validate_password_policy(self.password, self.email)
        return self


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = 900
    message: str = "Authentication successful"


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    is_superuser: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CurrentUserResponse(BaseModel):
    id: uuid.UUID
    email: str
    full_name: str
    is_active: bool
    is_superuser: bool
    created_at: datetime
    memberships: list[dict] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class UserMeResponse(UserResponse):
    pass


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=PASSWORD_MAX_LENGTH)
    # The full policy (common passwords, email name) is checked by the service,
    # which knows the account's email address.
    new_password: str = Field(..., min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
