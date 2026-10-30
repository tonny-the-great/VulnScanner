"""
Audit logger.

Every security-relevant action MUST call audit_log().
Audit records are append-only and must never contain secrets.

Sensitive field names automatically blocked from metadata:
    password, password_hash, secret, api_key, token, credential, key
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from sqlalchemy.orm import Session

from app.core.request_context import current_request_context

logger = structlog.get_logger(__name__)

_MAX_IP_LENGTH = 45
_MAX_USER_AGENT_LENGTH = 512

# Fields that are never allowed in audit metadata
_BLOCKED_METADATA_KEYS = frozenset({
    "password",
    "password_hash",
    "secret",
    "api_key",
    "token",
    "access_token",
    "refresh_token",
    "credential",
    "private_key",
    "key",
    "hash",
})


def _sanitize_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """
    Recursively remove blocked keys from metadata.
    Returns a clean copy — does not modify the input dict.
    """
    sanitized: dict[str, Any] = {}
    for k, v in metadata.items():
        if k.lower() in _BLOCKED_METADATA_KEYS:
            continue
        if isinstance(v, dict):
            sanitized[k] = _sanitize_metadata(v)
        else:
            sanitized[k] = v
    return sanitized


def audit_log(
    db: Session,
    *,
    action: str,
    object_type: str | None = None,
    object_id: str | uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | uuid.UUID | None = None,
    actor_id: str | uuid.UUID | None = None,
    actor_email: str | None = None,
    organization_id: str | uuid.UUID | None = None,
    metadata: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    commit: bool = True,
) -> None:
    """
    Record an audit entry.

    Success paths pass commit=False and commit once together with the action, so
    the action and its audit entry are persisted (or rolled back) atomically.
    Failure paths that audit and then raise keep commit=True: the entry must be
    stored even though the request ends in an error.

    ip_address and user_agent default to the current request's context, if any.
    """
    from app.models.audit import AuditLog

    context = current_request_context()
    if context is not None:
        if ip_address is None:
            ip_address = context.ip_address
        if user_agent is None:
            user_agent = context.user_agent

    clean_metadata = _sanitize_metadata(metadata or {})
    if actor_email:
        clean_metadata["actor_email"] = actor_email
    final_type = object_type or resource_type or "system"
    final_id = str(object_id or resource_id or "")

    entry = AuditLog(
        actor_id=uuid.UUID(str(actor_id)) if actor_id else None,
        organization_id=uuid.UUID(str(organization_id)) if organization_id else None,
        action=action,
        object_type=final_type,
        object_id=final_id,
        metadata_=clean_metadata,
        ip_address=ip_address[:_MAX_IP_LENGTH] if ip_address else None,
        user_agent=user_agent[:_MAX_USER_AGENT_LENGTH] if user_agent else None,
        timestamp=datetime.now(UTC),
    )
    db.add(entry)
    if commit:
        db.commit()

    # Application logs identify the actor by id only; the email stays in the database.
    logger.info(
        "audit",
        action=action,
        object_type=final_type,
        object_id=final_id,
        actor_id=str(actor_id) if actor_id else None,
        organization_id=str(organization_id) if organization_id else None,
    )


# ── Predefined action constants ───────────────────────────────────────────────
class AuditAction:
    # Auth
    AUTH_LOGIN = "auth.login"
    AUTH_LOGOUT = "auth.logout"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_ACCOUNT_LOCKED = "auth.account_locked"
    AUTH_PASSWORD_CHANGE = "auth.password_change"
    AUTH_REGISTER = "auth.register"
    AUTH_REFRESH_REUSE = "auth.refresh_reuse"

    # Organization
    ORG_CREATED = "org.created"
    ORG_UPDATED = "org.updated"
    ORG_MEMBER_ADDED = "org.member_added"
    ORG_MEMBER_REMOVED = "org.member_removed"
    USER_ASSIGN_ROLE = "user.assign_role"

    # Authorization
    AUTHZ_CREATE = "authz.create"
    AUTHZ_REVOKE = "authz.revoke"

    # Scan
    SCAN_CREATE = "scan.create"
    SCAN_CANCEL = "scan.cancel"
    SCAN_REAPED = "scan.reaped"

    # Asset
    ASSET_UPDATE = "asset.update"

    # Finding
    FINDING_UPDATE_STATUS = "finding.update_status"
    FINDING_ACCEPT_RISK = "finding.accept_risk"
    FINDING_ASSIGN = "finding.assign"
    FINDING_ADD_NOTE = "finding.add_note"
    FINDING_REOPENED = "finding.reopened"

    # Remediation & Report
    REMEDIATION_GENERATE = "remediation.generate"
    REPORT_GENERATE = "report.generate"
    REPORT_DOWNLOAD = "report.download"
