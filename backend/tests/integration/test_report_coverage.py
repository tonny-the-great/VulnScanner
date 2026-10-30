"""Reports distinguish missing coverage from assessments with no findings."""

import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.models.authorization import ScopeAuthorization
from app.models.finding import Finding, FindingConfidence, FindingSeverity, FindingStatus
from app.models.organization import Organization
from app.models.report import Report, ReportType
from app.models.scan import Scan, ScanProfile, ScanStatus
from app.models.user import User
from app.services.report_service import ReportService


@pytest.fixture
def report_lab(db, monkeypatch):
    tag = uuid.uuid4().hex
    owner = User(
        email=f"report-{tag}@example.com", full_name="Report Owner", password_hash="unused-fixture"
    )
    organization = Organization(name=f"Report Lab {tag}", slug=f"report-{tag}")
    profile = ScanProfile(name=f"report-{tag}", display_name="Report fixture", config_json={})
    db.add_all([owner, organization, profile])
    db.flush()
    authorization = ScopeAuthorization(
        organization_id=organization.id, title="Authorized report fixture",
        signer_name="Report Owner", signer_email=owner.email,
        authorization_date=datetime.now(UTC).date(), created_by=owner.id,
    )
    db.add(authorization)
    db.commit()

    def skip_pdf(**_kwargs):
        raise RuntimeError("Focused regression validates HTML only")

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=skip_pdf))

    def render(report_type, statuses=(), selected_scan=None, with_finding=False):
        scans = [Scan(
            organization_id=organization.id, authorization_id=authorization.id,
            profile_id=profile.id, created_by=owner.id, status=status,
            completed_at=datetime.now(UTC) if status == ScanStatus.COMPLETED else None,
        ) for status in statuses]
        db.add_all(scans)
        db.flush()
        if with_finding:
            db.add(Finding(
                organization_id=organization.id, title="Recorded fixture finding",
                description="Recorded by the authorized scanner", source_tool="fixture",
                confidence=FindingConfidence.CONFIRMED, severity=FindingSeverity.LOW,
                priority_score=2, fingerprint=uuid.uuid4().hex, status=FindingStatus.OPEN,
                first_seen_scan_id=scans[0].id, last_seen_scan_id=scans[0].id,
            ))
        report = Report(
            organization_id=organization.id,
            scan_id=scans[selected_scan].id if selected_scan is not None else None,
            report_type=report_type, title="Coverage report", generated_by=owner.id,
            access_token=uuid.uuid4().hex, token_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        db.add(report)
        db.commit()
        ReportService(db).build_report_files(report.id)
        return Path(report.html_path).read_text(encoding="utf-8")

    return render


@pytest.mark.parametrize("report_type", list(ReportType))
@pytest.mark.parametrize(
    "statuses", [(), (ScanStatus.FAILED,), (ScanStatus.CANCELLED, ScanStatus.TIMED_OUT)]
)
def test_empty_overview_explicitly_reports_missing_assessment_coverage(
    report_lab, report_type, statuses
):
    html = report_lab(report_type, statuses)
    assert f"0 of {len(statuses)} scans completed" in html
    assert "No findings are recorded in this report" in html
    assert "Assessment coverage needed" in html
    assert "No completed assessments are recorded" in html
    assert "before drawing conclusions about" in html
    assert "highest priority security risks identified during testing" not in html
    assert "No high risk findings identified" not in html


@pytest.mark.parametrize("report_type", list(ReportType))
def test_completed_zero_finding_overview_does_not_claim_clean_coverage(report_lab, report_type):
    html = report_lab(report_type, (ScanStatus.COMPLETED,))
    assert "1 of 1 scans completed" in html
    assert "No completed assessments are recorded" not in html
    assert "No findings are recorded in this report" in html
    assert "Review assessment coverage" in html


@pytest.mark.parametrize("report_type", list(ReportType))
def test_populated_overview_preserves_findings_and_reports_recorded_coverage(
    report_lab, report_type
):
    html = report_lab(report_type, (ScanStatus.COMPLETED, ScanStatus.FAILED), with_finding=True)
    assert "Recorded fixture finding" in html
    assert "1 of 2 scans completed" in html
    assert "No findings are recorded in this report" not in html
    if report_type == ReportType.EXECUTIVE:
        assert "highest priority findings recorded in this report" in html


@pytest.mark.parametrize("report_type", list(ReportType))
def test_single_incomplete_scan_retains_partial_assessment_notice(report_lab, report_type):
    html = report_lab(report_type, (ScanStatus.COMPLETED, ScanStatus.FAILED), selected_scan=1)
    assert "Scan status:</strong> failed" in html
    assert "Incomplete assessment" in html
    assert "partial results" in html
    assert "No findings are recorded in this report" in html
    assert "1 of 2 scans completed" not in html
