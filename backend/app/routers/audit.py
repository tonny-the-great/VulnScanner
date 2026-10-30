"""Audit log endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rbac import OrgAuthContext, require_role
from app.core.security import get_current_superuser
from app.database import get_db
from app.models.audit import AuditLog
from app.models.membership import UserRole
from app.models.user import User
from app.schemas.audit import AuditLogResponse

router = APIRouter(prefix="/organizations/{organization_id}/audit-log", tags=["Audit Log"])
# Platform events with no organization (logins, registrations, failed sign-ins).
platform_router = APIRouter(prefix="/audit-log", tags=["Audit Log"])


def _to_response(entry: AuditLog) -> AuditLogResponse:
    return AuditLogResponse(
        id=entry.id,
        organization_id=entry.organization_id,
        actor_id=entry.actor_id,
        actor_email=(entry.metadata_ or {}).get("actor_email"),
        ip_address=entry.ip_address,
        action=entry.action,
        resource_type=entry.object_type,
        resource_id=entry.object_id or None,
        metadata_sanitized=entry.metadata_ or {},
        created_at=entry.timestamp,
    )


@router.get("", response_model=list[AuditLogResponse])
def get_audit_log(
    organization_id: uuid.UUID,
    action: str | None = None,
    resource_type: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    auth_ctx: OrgAuthContext = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
) -> list[AuditLogResponse]:
    stmt = select(AuditLog).where(AuditLog.organization_id == organization_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if resource_type:
        stmt = stmt.where(AuditLog.object_type == resource_type)

    stmt = stmt.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)
    return [_to_response(entry) for entry in db.scalars(stmt).all()]


@platform_router.get("", response_model=list[AuditLogResponse])
def get_platform_audit_log(
    action: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    superuser: User = Depends(get_current_superuser),
    db: Session = Depends(get_db),
) -> list[AuditLogResponse]:
    """Platform-level audit entries (no organization), newest first. Superusers only."""
    stmt = select(AuditLog).where(AuditLog.organization_id.is_(None))
    if action:
        stmt = stmt.where(AuditLog.action == action)
    stmt = stmt.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)
    return [_to_response(entry) for entry in db.scalars(stmt).all()]
