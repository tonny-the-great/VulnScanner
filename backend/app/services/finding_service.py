"""Finding management and triage service."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.audit import AuditAction, audit_log
from app.core.exceptions import NotFoundError, ValidationError
from app.models.finding import (
    Finding,
    FindingAssignment,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    RemediationNote,
)
from app.models.membership import OrganizationMembership
from app.models.user import User


class FindingService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def list_findings(
        self,
        org_id: uuid.UUID,
        severity: FindingSeverity | None = None,
        status: FindingStatus | None = None,
        confidence: FindingConfidence | None = None,
        source_tool: str | None = None,
        asset_id: uuid.UUID | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Finding]:
        """
        Findings for list views. Evidence and notes are not loaded: list responses
        (FindingSummaryResponse) never read them, so no per-row queries are issued.
        """
        stmt = select(Finding).where(Finding.organization_id == org_id)

        if severity:
            stmt = stmt.where(Finding.severity == severity)
        if status:
            stmt = stmt.where(Finding.status == status)
        if confidence:
            stmt = stmt.where(Finding.confidence == confidence)
        if source_tool:
            stmt = stmt.where(Finding.source_tool == source_tool)
        if asset_id:
            stmt = stmt.where(Finding.asset_id == asset_id)
        if search:
            # autoescape: '%' and '_' in the search text match literally
            stmt = stmt.where(Finding.title.icontains(search, autoescape=True))

        # Finding.id breaks priority ties so pages are stable.
        stmt = (
            stmt.order_by(Finding.priority_score.desc().nullslast(), Finding.id)
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(stmt).all())

    def _load_finding(self, org_id: uuid.UUID, finding_id: uuid.UUID, *options: Any) -> Finding:
        stmt = (
            select(Finding)
            .where(
                Finding.id == finding_id,
                Finding.organization_id == org_id,
            )
            .options(*options)
        )
        finding = self.db.scalars(stmt).first()
        if not finding:
            raise NotFoundError(f"Finding {finding_id} not found")
        return finding

    def get_finding(self, org_id: uuid.UUID, finding_id: uuid.UUID) -> Finding:
        """A finding with its evidence and notes loaded, for the detail view."""
        return self._load_finding(
            org_id,
            finding_id,
            selectinload(Finding.evidence),
            selectinload(Finding.remediation_notes),
        )

    def update_status(
        self,
        org_id: uuid.UUID,
        finding_id: uuid.UUID,
        new_status: FindingStatus,
        actor: User,
        accepted_risk_reason: str | None = None,
    ) -> Finding:
        """
        Change a finding's triage status.

        Lifecycle fields always match the status: fixed_at is set only while the
        finding is FIXED, accepted_risk_at and accepted_risk_reason only while it
        is ACCEPTED_RISK. The reason is ignored for every other status.
        """
        finding = self._load_finding(org_id, finding_id)
        old_status = finding.status

        reason = accepted_risk_reason.strip() if accepted_risk_reason else None
        if new_status == FindingStatus.ACCEPTED_RISK and not reason:
            raise ValidationError(
                "A justification reason is required when accepting risk on a finding"
            )

        if new_status == old_status and (
            new_status != FindingStatus.ACCEPTED_RISK or reason == finding.accepted_risk_reason
        ):
            # Nothing changes: no write and no audit entry.
            return finding

        now = datetime.now(UTC)
        metadata: dict[str, Any] = {"old_status": old_status.value, "new_status": new_status.value}

        if old_status == FindingStatus.FIXED and new_status != FindingStatus.FIXED:
            fixed_at = finding.fixed_at
            metadata["previous_fixed_at"] = fixed_at.isoformat() if fixed_at else None
            finding.fixed_at = None
        if old_status == FindingStatus.ACCEPTED_RISK and new_status != FindingStatus.ACCEPTED_RISK:
            finding.accepted_risk_at = None
            finding.accepted_risk_reason = None

        if new_status == FindingStatus.FIXED:
            finding.fixed_at = now
        elif new_status == FindingStatus.ACCEPTED_RISK:
            # Also covers re-accepting with a new justification.
            finding.accepted_risk_at = now
            finding.accepted_risk_reason = reason
            metadata["accepted_risk_reason"] = reason

        finding.status = new_status

        action = (
            AuditAction.FINDING_ACCEPT_RISK
            if new_status == FindingStatus.ACCEPTED_RISK
            else AuditAction.FINDING_UPDATE_STATUS
        )
        audit_log(
            self.db,
            action=action,
            resource_type="finding",
            resource_id=str(finding.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata=metadata,
            commit=False,
        )
        self.db.commit()
        return self.get_finding(org_id, finding_id)

    def assign_finding(
        self,
        org_id: uuid.UUID,
        finding_id: uuid.UUID,
        target_user_id: uuid.UUID,
        actor: User,
    ) -> Finding:
        finding = self._load_finding(org_id, finding_id)

        is_member = self.db.scalars(
            select(OrganizationMembership.id).where(
                OrganizationMembership.organization_id == org_id,
                OrganizationMembership.user_id == target_user_id,
            )
        ).first()
        if not is_member:
            raise ValidationError("Assignee must be a member of this organization")

        # Deactivate previous active assignment
        stmt_prev = select(FindingAssignment).where(
            FindingAssignment.finding_id == finding.id,
            FindingAssignment.is_current,
        )
        for prev in self.db.scalars(stmt_prev).all():
            prev.is_current = False

        assignment = FindingAssignment(
            finding_id=finding.id,
            assigned_to=target_user_id,
            assigned_by=actor.id,
            is_current=True,
        )
        self.db.add(assignment)
        finding.assigned_to = target_user_id

        audit_log(
            self.db,
            action=AuditAction.FINDING_ASSIGN,
            resource_type="finding",
            resource_id=str(finding.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={"assigned_to": str(target_user_id)},
            commit=False,
        )
        self.db.commit()
        return self.get_finding(org_id, finding_id)

    def add_note(
        self,
        org_id: uuid.UUID,
        finding_id: uuid.UUID,
        note_text: str,
        actor: User,
    ) -> RemediationNote:
        finding = self._load_finding(org_id, finding_id)
        text = note_text.strip()
        if not text:
            raise ValidationError("A note cannot be empty")
        note = RemediationNote(
            finding_id=finding.id,
            author_id=actor.id,
            note=text,
            status_at_time=finding.status,
        )
        self.db.add(note)

        audit_log(
            self.db,
            action=AuditAction.FINDING_ADD_NOTE,
            resource_type="finding",
            resource_id=str(finding.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            commit=False,
        )
        self.db.commit()
        # Expired by the commit; its attributes reload when the response reads them.
        return note

    def list_notes(self, org_id: uuid.UUID, finding_id: uuid.UUID) -> list[RemediationNote]:
        self._load_finding(org_id, finding_id)
        stmt = (
            select(RemediationNote)
            .where(RemediationNote.finding_id == finding_id)
            .order_by(RemediationNote.created_at.desc())
        )
        return list(self.db.scalars(stmt).all())
