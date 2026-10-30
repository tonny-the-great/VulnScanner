"""
Stale scan reaper.

A worker that dies (container restart, OOM kill, host reboot) leaves its scan in
an active state forever, which also blocks the organization's concurrency slots.
Scans active for longer than SCAN_TIMEOUT plus SCAN_STALE_GRACE_SECONDS cannot
still be running (the orchestrator enforces SCAN_TIMEOUT), so they are closed.

Development scans that ran in an API background thread (rq_job_id "thread-...")
die with the API process; at API startup they are closed regardless of age.

Every transition is a compare-and-set on the status, so a scan that a live
worker finishes at the same moment is never overwritten.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.audit import AuditAction, audit_log
from app.models.scan import TERMINAL_SCAN_STATES, Scan, ScanEvent, ScanStatus

logger = logging.getLogger(__name__)

STALE_SCAN_MESSAGE = "Scan worker stopped before the scan finished; partial results may be missing"
THREAD_SCAN_MESSAGE = "The API restarted while this scan ran in a development background thread"
STALE_CANCEL_MESSAGE = "Scan cancelled; the worker stopped before confirming the cancellation"

_ACTIVE_STATES = (
    ScanStatus.VALIDATING,
    ScanStatus.RUNNING,
    ScanStatus.PARSING,
    ScanStatus.NORMALIZING,
)


@dataclass(frozen=True)
class _Reap:
    scan_id: uuid.UUID
    organization_id: uuid.UUID
    previous: ScanStatus
    message: str


def _plan(
    db: Session,
    organization_id: uuid.UUID | None,
    api_startup: bool,
    cutoff: datetime,
) -> dict[uuid.UUID, _Reap]:
    base = select(Scan.id, Scan.organization_id, Scan.status)
    if organization_id is not None:
        base = base.where(Scan.organization_id == organization_id)

    plan: dict[uuid.UUID, _Reap] = {}
    stale = base.where(
        Scan.status.in_((*_ACTIVE_STATES, ScanStatus.CANCEL_REQUESTED)),
        func.coalesce(Scan.started_at, Scan.queued_at) < cutoff,
    )
    for scan_id, org_id, status in db.execute(stale).all():
        message = (
            STALE_CANCEL_MESSAGE if status == ScanStatus.CANCEL_REQUESTED else STALE_SCAN_MESSAGE
        )
        plan[scan_id] = _Reap(scan_id, org_id, status, message)

    if api_startup:
        # The thread that ran these scans died with the previous API process.
        orphaned = base.where(
            Scan.status.not_in(tuple(TERMINAL_SCAN_STATES)),
            Scan.rq_job_id.like("thread-%"),
        )
        for scan_id, org_id, status in db.execute(orphaned).all():
            plan[scan_id] = _Reap(scan_id, org_id, status, THREAD_SCAN_MESSAGE)
    return plan


def reap_stale_scans(
    db: Session,
    *,
    organization_id: uuid.UUID | None = None,
    api_startup: bool = False,
    now: datetime | None = None,
) -> int:
    """Close abandoned scans; return how many were closed.

    Active scans older than the timeout plus grace period become FAILED and
    abandoned cancellation requests become CANCELLED. With api_startup, scans run
    by development background threads are closed regardless of age. Queued scans
    are otherwise left alone: they may still be waiting for a worker.
    """
    settings = get_settings()
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(
        seconds=settings.scan_timeout_seconds + settings.SCAN_STALE_GRACE_SECONDS
    )

    reaped = 0
    for item in _plan(db, organization_id, api_startup, cutoff).values():
        values: dict[str, object]
        if item.previous == ScanStatus.CANCEL_REQUESTED:
            new_status = ScanStatus.CANCELLED
            values = {"status": new_status, "cancelled_at": now}
        else:
            new_status = ScanStatus.FAILED
            values = {"status": new_status, "error_message": item.message}
        values["current_stage"] = new_status.value

        result = db.execute(
            update(Scan)
            .where(Scan.id == item.scan_id, Scan.status == item.previous)
            .values(**values)
        )
        if result.rowcount != 1:
            continue  # a live worker moved the scan on; leave it alone
        reaped += 1

        db.add(ScanEvent(
            scan_id=item.scan_id,
            event_type=f"scan_{new_status.value}",
            payload={"message": item.message, "reaped": True},
        ))
        audit_log(
            db,
            commit=False,
            action=AuditAction.SCAN_REAPED,
            resource_type="scan",
            resource_id=item.scan_id,
            organization_id=item.organization_id,
            metadata={"previous_status": item.previous.value, "new_status": new_status.value},
        )

    db.commit()
    if reaped:
        logger.warning("Closed %d abandoned scan(s) left active by a stopped worker", reaped)
    return reaped
