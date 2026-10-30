"""Scan orchestration and lifecycle service."""

from __future__ import annotations

import uuid
from collections import Counter
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, selectinload

from app.config import get_settings
from app.core.audit import AuditAction, audit_log
from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ScanStateError,
    ValidationError,
)
from app.models.authorization import ScopeAuthorization
from app.models.finding import Finding, ScanFindingSnapshot, finding_seen_in_scan
from app.models.organization import Organization
from app.models.scan import (
    TERMINAL_SCAN_STATES,
    Scan,
    ScanEvent,
    ScanProfile,
    ScanStatus,
    ScanTarget,
)
from app.models.user import User
from app.scanning.scope_gate import verify_scan_scope
from app.scanning.target_validator import validate_and_normalize_target
from app.services.scan_reaper import reap_stale_scans
from app.worker.queues import enqueue_job
from app.worker.tasks import run_scan_task

# Scans that occupy one of the organization's concurrency slots
_ACTIVE_SCAN_STATES = (
    ScanStatus.QUEUED,
    ScanStatus.VALIDATING,
    ScanStatus.RUNNING,
    ScanStatus.PARSING,
    ScanStatus.NORMALIZING,
    ScanStatus.CANCEL_REQUESTED,
)

_COMPARISON_NOTE = (
    "Resolved findings were not observed in the compared scan with matching targets "
    "and recorded scanner coverage. This does not verify that they were fixed."
)


def _comparison_targets(scan: Scan) -> frozenset[tuple[str, str]]:
    if not scan.targets or any(not target.scope_verified for target in scan.targets):
        raise ConflictError("Scan comparison requires nonempty, verified targets for both scans")
    try:
        return frozenset(
            (target_type.value, value)
            for target in scan.targets
            for target_type, value in [validate_and_normalize_target(target.target_value)]
        )
    except ValidationError:
        raise ConflictError("Scan comparison requires valid recorded targets") from None


def _comparison_coverage(
    events: list[ScanEvent], targets: frozenset[tuple[str, str]],
) -> tuple[dict, tuple[str, ...]]:
    """Require runtime provenance and successful, warning-free tool completion.

    A profile id is insufficient: built-in profiles are rewritten at startup and
    operators can change profiles between scans. Older scans have no immutable
    execution plan, so their coverage cannot safely be inferred from today's profile.
    """
    plans = [event.payload for event in events if event.event_type == "execution_plan"]
    if len(plans) != 1:
        raise ConflictError("Scan comparison requires recorded execution coverage; run fresh scans")
    plan = plans[0]
    if not isinstance(plan, dict) or type(plan.get("version")) is not int or plan["version"] != 1:
        raise ConflictError("Scan comparison cannot verify this execution coverage version")
    config, tools, recorded_targets = plan.get("config"), plan.get("tools"), plan.get("targets")
    if (
        not isinstance(config, dict)
        or not isinstance(config.get("is_intrusive"), bool)
        or not isinstance(tools, list)
        or not tools
        or any(not isinstance(tool, str) for tool in tools)
        or not isinstance(recorded_targets, list)
        or not recorded_targets
    ):
        raise ConflictError("Scan comparison cannot verify incomplete execution coverage")
    try:
        plan_targets = frozenset((target["type"], target["value"]) for target in recorded_targets)
        expected_tools = tuple(
            name for name in ("nmap", "nuclei", "testssl")
            if config.get(name, {}).get("enabled", name == "nmap")
        )
    except (KeyError, TypeError, AttributeError):
        raise ConflictError("Scan comparison cannot verify malformed execution coverage") from None
    if plan_targets != targets or tuple(tools) != expected_tools:
        raise ConflictError(
            "Scan comparison cannot verify the recorded targets and scanner coverage"
        )

    starts = [event.payload for event in events if event.event_type == "tool_started"]
    finishes = [event.payload for event in events if event.event_type == "tool_finished"]
    if any(not isinstance(payload, dict) for payload in starts + finishes):
        raise ConflictError("Scan comparison cannot verify scanner completion")
    expected = Counter(tools)
    # Requiring exactly one start and finish also refuses missing or duplicate
    # deliveries instead of treating an unexecuted tool as a clean result.
    if (
        any(not isinstance(payload.get("tool"), str) for payload in starts + finishes)
        or Counter(payload["tool"] for payload in starts) != expected
        or Counter(payload["tool"] for payload in finishes) != expected
    ):
        raise ConflictError("Scan comparison requires every planned scanner to have finished")
    if any(
        type(payload.get("exit_code")) is not int
        or payload["exit_code"] != 0
        or "error" not in payload
        or payload["error"] is not None
        or payload.get("warnings") != []
        for payload in finishes
    ):
        raise ConflictError(
            "Scan comparison requires successful scanner coverage "
            "without warnings or skipped checks"
        )
    return config, tuple(tools)


class ScanService:
    def __init__(self, db: Session) -> None:
        self.db = db

    def create_and_enqueue_scan(
        self,
        org_id: uuid.UUID,
        auth_id: uuid.UUID,
        profile_id: uuid.UUID,
        targets: list[str],
        intrusive_acknowledged: bool,
        actor: User,
    ) -> Scan:
        """Validate scope, check concurrency limits, persist scan and dispatch worker job."""
        if not targets:
            raise ValidationError("At least one target must be specified")
        if len(targets) > get_settings().MAX_TARGETS_PER_SCAN:
            raise ValidationError("Maximum targets per scan exceeded")

        # Scans abandoned by a dead worker must not hold concurrency slots forever.
        reap_stale_scans(self.db, organization_id=org_id)

        # 1. Lock the Organization row and check the concurrency limit. On
        # PostgreSQL the row lock is held until the single commit below, so
        # concurrent requests cannot both pass the check. SQLite ignores FOR UPDATE
        # and runs this count outside a write transaction, so there the limit is
        # best-effort (SQLite is for development only).
        org = self.db.scalars(
            select(Organization)
            .where(Organization.id == org_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if not org or not org.is_active:
            raise NotFoundError("Organization not found or inactive")

        active_count_stmt = select(func.count(Scan.id)).where(
            Scan.organization_id == org_id,
            Scan.status.in_(_ACTIVE_SCAN_STATES),
        )
        active_scans = self.db.scalar(active_count_stmt) or 0
        if active_scans >= org.max_concurrent_scans:
            raise ConflictError(
                f"Maximum concurrent scans limit ({org.max_concurrent_scans}) "
                "reached for organization"
            )

        # 2. Fetch and verify ScopeAuthorization
        stmt_auth = select(ScopeAuthorization).where(
            ScopeAuthorization.id == auth_id,
            ScopeAuthorization.organization_id == org_id,
        )
        authorization = self.db.scalars(stmt_auth).first()
        if not authorization:
            raise NotFoundError("Scope authorization not found for this organization")

        # 3. Fetch and verify ScanProfile
        profile = self.db.get(ScanProfile, profile_id)
        if not profile or not profile.is_enabled:
            raise NotFoundError("Scan profile not found or disabled")
        if profile.organization_id not in (None, org_id):
            raise NotFoundError("Scan profile not found for this organization")

        if profile.is_intrusive and not intrusive_acknowledged:
            raise PermissionDeniedError(
                "Profile is intrusive and requires explicit user acknowledgement before scanning"
            )

        # 4. Validate targets & verify scope gate
        validated_targets: list[tuple[Any, str]] = []
        for t in targets:
            t_type, norm = validate_and_normalize_target(t)
            validated_targets.append((t_type, norm))

        verify_scan_scope(authorization, validated_targets)

        # 5. Create Scan and ScanTargets
        scan = Scan(
            organization_id=org_id,
            authorization_id=auth_id,
            profile_id=profile_id,
            created_by=actor.id,
            status=ScanStatus.QUEUED,
        )
        self.db.add(scan)
        self.db.flush()

        for t_type, norm in validated_targets:
            scan_target = ScanTarget(
                scan_id=scan.id,
                target_value=norm,
                target_type=t_type,
                scope_verified=True,
            )
            self.db.add(scan_target)

        audit_log(
            self.db,
            commit=False,
            action=AuditAction.SCAN_CREATE,
            resource_type="scan",
            resource_id=str(scan.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
            metadata={"profile": profile.name, "targets": [v for _, v in validated_targets]},
        )
        # One commit for the scan, its targets and the audit entry; releases the org lock.
        self.db.commit()
        self.db.refresh(scan)

        # 6. Dispatch background worker job (after the commit: the worker must see the scan)
        try:
            job_id = enqueue_job("scans", run_scan_task, str(scan.id))
        except Exception as exc:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Background queue is unavailable; scan was not dispatched"
            self.db.commit()
            raise ConflictError(scan.error_message) from exc
        scan.rq_job_id = job_id
        self.db.commit()

        return scan

    def list_scans(self, org_id: uuid.UUID, limit: int = 50, offset: int = 0) -> list[Scan]:
        stmt = (
            select(Scan)
            .options(selectinload(Scan.targets))
            .where(Scan.organization_id == org_id)
            .order_by(Scan.queued_at.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.db.scalars(stmt).all())

    def get_scan(self, org_id: uuid.UUID, scan_id: uuid.UUID) -> Scan:
        stmt = (
            select(Scan)
            .options(selectinload(Scan.targets))
            .where(
                Scan.id == scan_id,
                Scan.organization_id == org_id,
            )
        )
        scan = self.db.scalars(stmt).first()
        if not scan:
            raise NotFoundError(f"Scan {scan_id} not found")
        return scan

    def cancel_scan(self, org_id: uuid.UUID, scan_id: uuid.UUID, actor: User) -> Scan:
        scan = self.get_scan(org_id, scan_id)
        if scan.status in TERMINAL_SCAN_STATES:
            raise ScanStateError(f"Cannot cancel scan in terminal state {scan.status.value}")

        if scan.status == ScanStatus.CANCEL_REQUESTED:
            return scan
        result = self.db.execute(
            update(Scan).where(Scan.id == scan.id, Scan.status == scan.status)
            .values(status=ScanStatus.CANCEL_REQUESTED)
        )
        if result.rowcount != 1:
            self.db.rollback()
            raise ScanStateError("Scan state changed; refresh before cancelling")

        audit_log(
            self.db,
            commit=False,
            action=AuditAction.SCAN_CANCEL,
            resource_type="scan",
            resource_id=str(scan.id),
            organization_id=org_id,
            actor_id=actor.id,
            actor_email=actor.email,
        )
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def compare_scans(
        self, org_id: uuid.UUID, base_scan_id: uuid.UUID, compared_scan_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Compare observations only when both scans have equivalent recorded coverage."""
        base_scan = self.get_scan(org_id, base_scan_id)
        compared_scan = self.get_scan(org_id, compared_scan_id)
        if any(
            scan.status != ScanStatus.COMPLETED or scan.error_message
            for scan in (base_scan, compared_scan)
        ):
            raise ConflictError(
                "Scan comparison requires both scans to have completed successfully"
            )
        base_targets = _comparison_targets(base_scan)
        compared_targets = _comparison_targets(compared_scan)
        if base_targets != compared_targets:
            raise ConflictError("Scan comparison requires matching target sets")
        events = list(self.db.scalars(select(ScanEvent).where(
            ScanEvent.scan_id.in_((base_scan_id, compared_scan_id)),
            ScanEvent.event_type.in_(("execution_plan", "tool_started", "tool_finished")),
        )).all())
        base_coverage = _comparison_coverage(
            [event for event in events if event.scan_id == base_scan_id], base_targets,
        )
        compared_coverage = _comparison_coverage(
            [event for event in events if event.scan_id == compared_scan_id], compared_targets,
        )
        if base_coverage != compared_coverage:
            raise ConflictError("Scan comparison requires matching recorded scanner configurations")

        # Findings observed by each scan (per-scan sightings, not only first/last scan)
        stmt_base = select(Finding).where(
            Finding.organization_id == org_id,
            finding_seen_in_scan(base_scan_id),
        )
        base_findings = {f.id: f for f in self.db.scalars(stmt_base).all()}

        stmt_comp = select(Finding).where(
            Finding.organization_id == org_id,
            finding_seen_in_scan(compared_scan_id),
        )
        comp_findings = {f.id: f for f in self.db.scalars(stmt_comp).all()}

        # Stable finding ids preserve continuity when a legacy fingerprint is re-keyed.
        new_ids = set(comp_findings) - set(base_findings)
        absent_ids = set(base_findings) - set(comp_findings)
        persistent_ids = set(base_findings) & set(comp_findings)
        snapshots = {
            (snapshot.scan_id, snapshot.finding_id): snapshot
            for snapshot in self.db.scalars(select(ScanFindingSnapshot).where(
                ScanFindingSnapshot.scan_id.in_((base_scan_id, compared_scan_id)),
            )).all()
        }

        def summarize(f: Finding, scan_id: uuid.UUID) -> dict:
            snapshot = snapshots.get((scan_id, f.id))
            return {
                "id": str(f.id),
                "title": snapshot.data["title"] if snapshot is not None else f.title,
                "severity": snapshot.severity.value if snapshot is not None else f.severity.value,
                "fingerprint": (
                    snapshot.data["fingerprint"] if snapshot is not None else f.fingerprint
                ),
            }

        return {
            "base_scan_id": base_scan_id,
            "compared_scan_id": compared_scan_id,
            "comparison_note": _COMPARISON_NOTE,
            "new_findings_count": len(new_ids),
            "resolved_findings_count": len(absent_ids),
            "persistent_findings_count": len(persistent_ids),
            "new_findings": [
                summarize(comp_findings[finding_id], compared_scan_id)
                for finding_id in sorted(new_ids)
            ],
            "resolved_findings": [
                summarize(base_findings[finding_id], base_scan_id)
                for finding_id in sorted(absent_ids)
            ],
            "persistent_findings": [
                summarize(comp_findings[finding_id], compared_scan_id)
                for finding_id in sorted(persistent_ids)
            ],
        }
