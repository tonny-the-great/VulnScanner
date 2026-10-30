"""Scope authorization service."""

from __future__ import annotations

import uuid
from datetime import UTC, date, datetime
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from app.config import get_settings
from app.core.audit import AuditAction, audit_log
from app.core.exceptions import NotFoundError, ValidationError
from app.models.authorization import AuthorizedTarget, ScopeAuthorization
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.scanning.target_validator import validate_and_normalize_target

# Unfinished scans that a revocation moves to CANCEL_REQUESTED
_CANCELLABLE_SCAN_STATES = (
    ScanStatus.QUEUED,
    ScanStatus.VALIDATING,
    ScanStatus.RUNNING,
    ScanStatus.PARSING,
    ScanStatus.NORMALIZING,
)


class AuthorizationService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_authorization(
        self,
        org_id: uuid.UUID,
        title: str,
        signer_name: str,
        signer_email: str,
        authorization_date: date,
        expiration_date: date | None,
        notes: str | None,
        targets: list[dict],
        actor: User,
        document_filename: str | None = None,
        document_bytes: bytes | None = None,
    ) -> ScopeAuthorization:
        """Create a new ScopeAuthorization record and its canonical AuthorizedTargets."""
        if expiration_date and expiration_date < authorization_date:
            raise ValidationError("Expiration date cannot be earlier than authorization date")

        # Handle document upload safely
        doc_path: str | None = None
        if document_bytes and document_filename:
            settings = get_settings()
            auth_dir = Path(settings.upload_dir) / "authorizations"
            auth_dir.mkdir(parents=True, exist_ok=True)
            safe_ext = Path(document_filename).suffix.lower()
            if safe_ext not in (".pdf", ".png", ".jpg", ".jpeg", ".docx"):
                raise ValidationError("Only PDF, PNG, JPG, or DOCX documents are allowed")

            saved_name = f"{uuid.uuid4()}{safe_ext}"
            saved_file = auth_dir / saved_name
            with open(saved_file, "wb") as f:
                f.write(document_bytes)
            doc_path = str(saved_file)

        auth = ScopeAuthorization(
            organization_id=org_id,
            title=title.strip(),
            signer_name=signer_name.strip(),
            signer_email=signer_email.strip().lower(),
            authorization_date=authorization_date,
            expiration_date=expiration_date,
            document_path=doc_path,
            notes=notes,
            created_by=actor.id,
        )
        self.db.add(auth)
        self.db.flush()

        # Validate and add authorized targets
        for t in targets:
            val = t.get("value", "")
            t_notes = t.get("notes")
            t_type, norm_val = validate_and_normalize_target(val)
            auth_target = AuthorizedTarget(
                authorization_id=auth.id,
                target_type=t_type,
                value=norm_val,
                notes=t_notes,
            )
            self.db.add(auth_target)

        self.db.commit()
        self.db.refresh(auth)

        audit_log(
            self.db,
            action=AuditAction.AUTHZ_CREATE,
            resource_type="scope_authorization",
            resource_id=str(auth.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={
                "title": auth.title,
                "signer": auth.signer_name,
                "targets_count": len(targets),
            },
        )

        return auth

    def list_authorizations(
        self, org_id: uuid.UUID, limit: int = 100, offset: int = 0
    ) -> list[ScopeAuthorization]:
        stmt = (
            select(ScopeAuthorization)
            .options(selectinload(ScopeAuthorization.authorized_targets))
            .where(ScopeAuthorization.organization_id == org_id)
            .order_by(ScopeAuthorization.created_at.desc(), ScopeAuthorization.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(stmt).all())

    def get_authorization(self, org_id: uuid.UUID, auth_id: uuid.UUID) -> ScopeAuthorization:
        stmt = (
            select(ScopeAuthorization)
            .options(selectinload(ScopeAuthorization.authorized_targets))
            .where(
                ScopeAuthorization.id == auth_id,
                ScopeAuthorization.organization_id == org_id,
            )
        )
        auth = self.db.scalars(stmt).first()
        if not auth:
            raise NotFoundError(f"ScopeAuthorization {auth_id} not found")
        return auth

    def revoke_authorization(
        self,
        org_id: uuid.UUID,
        auth_id: uuid.UUID,
        actor: User,
    ) -> ScopeAuthorization:
        """
        Revoke an authorization and request cancellation of its unfinished scans.

        Scans without a valid authorization must not keep running; the worker's
        cancel path stops any scanner process that is already running.
        """
        auth = self.get_authorization(org_id, auth_id)
        if auth.is_revoked:
            return auth

        auth.is_revoked = True
        auth.revoked_at = datetime.now(UTC)
        auth.revoked_by = actor.id

        # One guarded UPDATE: a scan that finished meanwhile is left alone, and
        # RETURNING lists exactly the scans that were moved to cancel_requested.
        cancelled_scan_ids = list(self.db.scalars(
            update(Scan)
            .where(
                Scan.authorization_id == auth.id,
                Scan.status.in_(_CANCELLABLE_SCAN_STATES),
            )
            .values(status=ScanStatus.CANCEL_REQUESTED)
            .returning(Scan.id),
            execution_options={"synchronize_session": False},
        ).all())

        audit_log(
            self.db,
            commit=False,
            action=AuditAction.AUTHZ_REVOKE,
            resource_type="scope_authorization",
            resource_id=str(auth.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={
                "title": auth.title,
                "cancelled_scan_ids": [str(scan_id) for scan_id in cancelled_scan_ids],
            },
        )
        self.db.commit()
        self.db.refresh(auth)
        return auth
