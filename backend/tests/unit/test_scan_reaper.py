"""Stale scan reaper: abandoned scans are closed, live and queued scans are not."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.config import get_settings
from app.core.audit import AuditAction
from app.models.audit import AuditLog
from app.models.authorization import ScopeAuthorization
from app.models.organization import Organization
from app.models.scan import Scan, ScanEvent, ScanProfile, ScanStatus
from app.models.user import User
from app.services.scan_reaper import STALE_SCAN_MESSAGE, THREAD_SCAN_MESSAGE, reap_stale_scans


@pytest.fixture
def org_setup(db):
    tag = uuid.uuid4().hex[:12]
    # The account never logs in, so any placeholder hash will do.
    user = User(
        email=f"reaper-{tag}@example.com",
        display_name="Reaper",
        password_hash="unused-placeholder-hash",
    )
    org = Organization(name=f"Reaper {tag}", slug=f"reaper-{tag}")
    db.add_all([user, org])
    db.flush()
    authorization = ScopeAuthorization(
        organization_id=org.id, title="Reaper test", signer_name="Reaper", signer_email=user.email,
        authorization_date=datetime.now(UTC).date(), created_by=user.id,
    )
    profile = ScanProfile(
        organization_id=org.id, name=f"reaper-{tag}", display_name="Reaper profile", config_json={}
    )
    db.add_all([authorization, profile])
    db.commit()

    def make_scan(status, *, age=timedelta(0), started=True, job="rq-job"):
        moment = datetime.now(UTC) - age
        scan = Scan(
            organization_id=org.id, authorization_id=authorization.id, profile_id=profile.id,
            created_by=user.id, status=status, rq_job_id=job, queued_at=moment,
            started_at=moment if started else None,
        )
        db.add(scan)
        db.commit()
        return scan.id

    return org.id, make_scan


def stale_age():
    settings = get_settings()
    return timedelta(seconds=settings.scan_timeout_seconds + settings.SCAN_STALE_GRACE_SECONDS + 60)


def status_of(db, scan_id):
    db.expire_all()
    return db.get(Scan, scan_id)


def test_abandoned_running_scan_fails(db, org_setup):
    org_id, make_scan = org_setup
    scan_id = make_scan(ScanStatus.RUNNING, age=stale_age())
    assert reap_stale_scans(db, organization_id=org_id) == 1
    scan = status_of(db, scan_id)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == STALE_SCAN_MESSAGE
    event = db.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan_id)).one()
    assert event.event_type == "scan_failed"
    assert event.payload == {"message": STALE_SCAN_MESSAGE, "reaped": True}
    audit = db.scalars(select(AuditLog).where(AuditLog.object_id == str(scan_id))).one()
    assert audit.action == AuditAction.SCAN_REAPED
    assert audit.organization_id == org_id
    assert audit.metadata_ == {"previous_status": "running", "new_status": "failed"}
    # Already terminal: a second pass changes nothing.
    assert reap_stale_scans(db, organization_id=org_id) == 0


def test_abandoned_cancellation_completes(db, org_setup):
    org_id, make_scan = org_setup
    scan_id = make_scan(ScanStatus.CANCEL_REQUESTED, age=stale_age(), started=False)
    assert reap_stale_scans(db, organization_id=org_id) == 1
    scan = status_of(db, scan_id)
    assert scan.status == ScanStatus.CANCELLED
    assert scan.cancelled_at is not None
    event = db.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan_id)).one()
    assert event.event_type == "scan_cancelled" and event.payload["reaped"] is True


def test_recent_and_queued_scans_are_untouched(db, org_setup):
    org_id, make_scan = org_setup
    fresh = make_scan(ScanStatus.RUNNING, age=timedelta(minutes=5))
    old_queued = make_scan(ScanStatus.QUEUED, age=stale_age(), started=False)
    assert reap_stale_scans(db, organization_id=org_id) == 0
    assert status_of(db, fresh).status == ScanStatus.RUNNING
    assert status_of(db, old_queued).status == ScanStatus.QUEUED


def test_now_parameter_controls_the_cutoff(db, org_setup):
    org_id, make_scan = org_setup
    scan_id = make_scan(ScanStatus.PARSING, age=timedelta(minutes=5))
    assert reap_stale_scans(db, organization_id=org_id) == 0
    assert reap_stale_scans(db, organization_id=org_id, now=datetime.now(UTC) + stale_age()) == 1
    assert status_of(db, scan_id).status == ScanStatus.FAILED


def test_thread_jobs_are_failed_only_at_api_startup(db, org_setup):
    org_id, make_scan = org_setup
    queued = make_scan(ScanStatus.QUEUED, started=False, job="thread-1234")
    running = make_scan(ScanStatus.RUNNING, job="thread-5678")
    rq_job = make_scan(ScanStatus.RUNNING, job="rq-abc")
    assert reap_stale_scans(db, organization_id=org_id) == 0
    assert status_of(db, queued).status == ScanStatus.QUEUED

    assert reap_stale_scans(db, organization_id=org_id, api_startup=True) == 2
    for scan_id in (queued, running):
        scan = status_of(db, scan_id)
        assert scan.status == ScanStatus.FAILED
        assert scan.error_message == THREAD_SCAN_MESSAGE
    assert status_of(db, rq_job).status == ScanStatus.RUNNING


def test_organization_filter_limits_candidates(db, org_setup):
    org_id, make_scan = org_setup
    scan_id = make_scan(ScanStatus.RUNNING, age=stale_age())
    assert reap_stale_scans(db, organization_id=uuid.uuid4()) == 0
    assert status_of(db, scan_id).status == ScanStatus.RUNNING
    assert reap_stale_scans(db, organization_id=org_id) == 1
