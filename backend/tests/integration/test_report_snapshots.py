"""Historical reports retain scanner observations after later scans and triage.

The lab exercises real normalization, persistence, workflow changes and HTML
artifact generation. It never invokes a scanner, queue, PDF renderer or network.
"""

import re
import uuid
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import delete, func, select

from app.models.asset import Asset, AssetType
from app.models.authorization import ScopeAuthorization
from app.models.finding import (
    Finding,
    FindingConfidence,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    ScanFinding,
    ScanFindingSnapshot,
)
from app.models.organization import Organization
from app.models.report import Report, ReportType
from app.models.scan import Scan, ScanProfile, ScanStatus
from app.models.user import User
from app.scanning.adapters.base import RawFinding, RawFindingEvidence
from app.scanning.normalization import FindingDeduplicator, normalize_raw_finding
from app.services.finding_service import FindingService
from app.services.report_service import ReportService


@pytest.fixture
def snapshot_lab(db):
    tag = uuid.uuid4().hex
    owner = User(
        email=f"snapshot-{tag}@example.com", full_name="Snapshot Owner",
        password_hash="unused-fixture",
    )
    organization = Organization(name=f"Snapshot Lab {tag}", slug=f"snapshot-{tag}")
    profile = ScanProfile(
        name=f"snapshot-{tag}", display_name="Snapshot fixture", config_json={},
    )
    db.add_all([owner, organization, profile])
    db.flush()
    authorization = ScopeAuthorization(
        organization_id=organization.id, title="Authorized snapshot fixture",
        signer_name=owner.full_name, signer_email=owner.email,
        authorization_date=datetime.now(UTC).date(), created_by=owner.id,
    )
    asset = Asset(
        organization_id=organization.id, asset_type=AssetType.IPV4,
        ip_address="10.60.70.80", discovery_source="snapshot-fixture",
    )
    db.add_all([authorization, asset])
    db.commit()
    org_id, owner_id = organization.id, owner.id
    auth_id, profile_id = authorization.id, profile.id

    def new_scan():
        scan = Scan(
            organization_id=org_id, authorization_id=auth_id,
            profile_id=profile_id, created_by=owner_id,
            status=ScanStatus.RUNNING, started_at=datetime.now(UTC),
        )
        db.add(scan)
        db.commit()
        return scan

    def persist(raws, scan, *, linked_asset=None, commit=True):
        normalized = [normalize_raw_finding(raw, org_id, linked_asset, None) for raw in raws]
        findings = FindingDeduplicator(db, org_id).upsert_findings(normalized, scan.id)
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(UTC)
        scan.findings_count = len({finding.id for finding in findings})
        if commit:
            db.commit()
        return findings

    def new_report(report_type, scan=None):
        report = Report(
            organization_id=org_id, scan_id=scan.id if scan is not None else None,
            report_type=report_type, title="Historical accuracy regression",
            generated_by=owner_id, access_token=uuid.uuid4().hex,
            token_expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        db.add(report)
        db.commit()
        return report

    def render(report):
        return ReportService(db).build_html(report).read_text(encoding="utf-8")

    def status(finding, value):
        return FindingService(db).update_status(org_id, finding.id, value, actor=owner)

    return SimpleNamespace(
        org_id=org_id, asset=asset, new_scan=new_scan, persist=persist,
        new_report=new_report, render=render, status=status,
    )


def observation(index=1, *, severity=FindingSeverity.LOW, cvss=3.0,
                confidence=FindingConfidence.UNVERIFIED, evidence=("Original banner",),
                extra_identifiers=False):
    # Adding a higher-sorted CVE preserves the primary CVE and fingerprint.
    cves = [f"CVE-2026-{index}000"]
    cwes = ["CWE-200"]
    if extra_identifiers:
        cves.append(f"CVE-2026-{index}999")
        cwes.append("CWE-319")
    return RawFinding(
        title=f"Historical fixture finding {index}",
        description=f"Original scanner description {index}",
        source_tool="nmap", scanner_reference=f"snapshot-fixture-{index}",
        confidence=confidence, cve_ids=cves, cwe_ids=cwes,
        severity=severity, cvss_score=cvss, port=443, protocol="tcp",
        target_address="10.60.70.80",
        evidence=[RawFindingEvidence(evidence_type="banner", content=text) for text in evidence],
    )


def severity_order(html):
    return re.findall(r'<span class="badge ([a-z]+)">\1</span>', html)


def card_value(html, title):
    match = re.search(
        r'<div class="card-title">' + re.escape(title)
        + r'</div>\s*<div class="card-value"[^>]*>(\d+)</div>', html,
    )
    assert match is not None, f"Missing report metric: {title}"
    return int(match.group(1))


@pytest.mark.parametrize("report_type", list(ReportType))
def test_scan_reports_preserve_original_state_and_rank_while_overviews_stay_current(
    db, snapshot_lab, report_type,
):
    lab = snapshot_lab
    first_scan = lab.new_scan()
    first, second = lab.persist([
        observation(1, evidence=("First scan evidence one",)),
        observation(2, severity=FindingSeverity.MEDIUM, cvss=6.0,
                    confidence=FindingConfidence.LIKELY, evidence=("First scan evidence two",)),
    ], first_scan)
    original_priorities = [float(first.priority_score), float(second.priority_score)]
    assert original_priorities[0] < original_priorities[1]
    first_report = lab.new_report(report_type, first_scan)
    first_html = lab.render(first_report)
    assert severity_order(first_html) == ["medium", "low"]
    assert first_html.index(second.title) < first_html.index(first.title)
    if report_type == ReportType.EXECUTIVE:
        assert card_value(first_html, "Total Findings") == 2
        assert card_value(first_html, "Critical & High") == 0
        assert card_value(first_html, "Assets With Findings") == 0
        assert first_html.count("<td>open</td>") == 2
    else:
        assert first_html.count("Status at observation:</strong> open") == 2
        assert "First scan evidence one" in first_html
        assert "First scan evidence two" in first_html
        assert "Confidence:</strong> unverified" in first_html

    # Triage changes after scan one must not revise its report. A fixed finding
    # is reopened by re-detection; an in-progress finding keeps its workflow state.
    lab.status(first, FindingStatus.FIXED)
    lab.status(second, FindingStatus.IN_PROGRESS)
    second_scan = lab.new_scan()
    again_first, again_second = lab.persist([
        observation(1, severity=FindingSeverity.CRITICAL, cvss=9.8,
                    confidence=FindingConfidence.CONFIRMED,
                    evidence=("Second scan evidence one",), extra_identifiers=True),
        observation(2, severity=FindingSeverity.HIGH, cvss=8.0,
                    confidence=FindingConfidence.CONFIRMED,
                    evidence=("Second scan evidence two",), extra_identifiers=True),
    ], second_scan, linked_asset=lab.asset)
    assert [again_first.id, again_second.id] == [first.id, second.id]
    assert float(again_first.priority_score) > float(again_second.priority_score)
    second_report = lab.new_report(report_type, second_scan)
    second_html = lab.render(second_report)
    assert severity_order(second_html) == ["critical", "high"]
    assert second_html.index(first.title) < second_html.index(second.title)
    if report_type == ReportType.EXECUTIVE:
        assert card_value(second_html, "Critical & High") == 2
        assert card_value(second_html, "Assets With Findings") == 1
        assert "<td>open</td>" in second_html
        assert "<td>in_progress</td>" in second_html
    else:
        assert "Status at observation:</strong> open" in second_html
        assert "Status at observation:</strong> in_progress" in second_html
        assert "Second scan evidence one" in second_html
        assert "First scan evidence one" not in second_html
        assert "CVE-2026-1999" in second_html
        assert "CWE-319" in second_html

    # Account workflow and display fields remain mutable in current findings.
    lab.status(first, FindingStatus.FALSE_POSITIVE)
    lab.status(second, FindingStatus.FIXED)
    first.title = "Current finding title edited after both scans"
    first.description = "Current description edited after both scans"
    db.commit()
    assert lab.render(first_report) == first_html
    assert lab.render(second_report) == second_html
    assert "Historical finding snapshots are unavailable" not in first_html + second_html

    current_html = lab.render(lab.new_report(report_type))
    assert severity_order(current_html) == ["critical", "high"]
    assert "Current finding title edited after both scans" in current_html
    assert "Historical finding snapshots are unavailable" not in current_html
    if report_type == ReportType.EXECUTIVE:
        assert card_value(current_html, "Critical & High") == 2
        assert card_value(current_html, "Organization Assets") == 1
        assert "<td>false_positive</td>" in current_html
        assert "<td>fixed</td>" in current_html
    else:
        assert "Status:</strong> false_positive" in current_html
        assert "Status:</strong> fixed" in current_html
        assert "Current description edited after both scans" in current_html
        assert "Second scan evidence one" in current_html
        assert "First scan evidence one" not in current_html
    # Rendering historical values must never overwrite the session's live models.
    assert first.status == FindingStatus.FALSE_POSITIVE
    assert second.status == FindingStatus.FIXED
    assert first.severity == FindingSeverity.CRITICAL
    assert second.severity == FindingSeverity.HIGH
    assert float(first.priority_score) > original_priorities[0]


def test_snapshot_keeps_repeated_and_new_evidence_of_the_same_type(db, snapshot_lab):
    lab = snapshot_lab
    evidence_a = "Banner A <original>"
    evidence_b = "Banner B & additional"
    evidence_c = "Banner C from a later scan"
    first_scan = lab.new_scan()
    finding = lab.persist([observation(evidence=(evidence_a,))], first_scan)[0]
    second_scan = lab.new_scan()
    lab.persist([observation(evidence=(evidence_a, evidence_b, evidence_a))], second_scan)
    stored_second = list(db.scalars(select(FindingEvidence).where(
        FindingEvidence.finding_id == finding.id, FindingEvidence.scan_id == second_scan.id,
    )))
    assert [row.content for row in stored_second] == [evidence_b]

    second_report = lab.new_report(ReportType.TECHNICAL, second_scan)
    second_html = lab.render(second_report)
    assert "Banner A &lt;original&gt;" in second_html
    assert "Banner B &amp; additional" in second_html
    assert second_html.count("Banner A &lt;original&gt;") == 1
    assert "Banner A <original>" not in second_html

    third_scan = lab.new_scan()
    lab.persist([observation(evidence=(evidence_b, evidence_c))], third_scan)
    assert lab.render(second_report) == second_html
    assert evidence_c not in second_html
    third_html = lab.render(lab.new_report(ReportType.TECHNICAL, third_scan))
    assert "Banner B &amp; additional" in third_html
    assert evidence_c in third_html
    assert "Banner A &lt;original&gt;" not in third_html


@pytest.mark.parametrize("report_type", list(ReportType))
def test_legacy_scan_report_explicitly_labels_current_finding_state(
    db, snapshot_lab, report_type,
):
    lab = snapshot_lab
    legacy_scan = lab.new_scan()
    finding = lab.persist([observation(evidence=("Legacy scan evidence",))], legacy_scan)[0]
    db.execute(delete(ScanFindingSnapshot).where(ScanFindingSnapshot.scan_id == legacy_scan.id))
    db.commit()
    later_scan = lab.new_scan()
    lab.persist([observation(
        severity=FindingSeverity.CRITICAL, cvss=9.8,
        confidence=FindingConfidence.CONFIRMED, evidence=("Later scan evidence",),
    )], later_scan)
    lab.status(finding, FindingStatus.IN_PROGRESS)

    html = lab.render(lab.new_report(report_type, legacy_scan))
    assert "Historical finding snapshots are unavailable" in html
    assert "current finding state" in html
    assert severity_order(html) == ["critical"]
    if report_type == ReportType.EXECUTIVE:
        assert "in_progress (current; snapshot unavailable)" in html
    else:
        assert "Status:</strong> in_progress" in html
        assert "Status at observation:</strong>" not in html
        assert "Legacy scan evidence" in html
        assert "Later scan evidence" not in html


def test_repeated_persistence_cannot_rewrite_an_existing_scan_snapshot(db, snapshot_lab):
    lab = snapshot_lab
    scan = lab.new_scan()
    finding = lab.persist([observation()], scan)[0]
    snapshot = db.get(ScanFindingSnapshot, (scan.id, finding.id))
    original_data = deepcopy(snapshot.data)
    original_captured_at = snapshot.captured_at
    report = lab.new_report(ReportType.TECHNICAL, scan)
    original_html = lab.render(report)
    lab.status(finding, FindingStatus.IN_PROGRESS)

    # A retry can occur after workflow changes; its sighting already exists.
    lab.persist([observation(
        severity=FindingSeverity.CRITICAL, cvss=9.8, evidence=("Retry-only evidence",),
    )], scan)
    db.refresh(snapshot)
    assert snapshot.data == original_data
    assert snapshot.captured_at == original_captured_at
    assert snapshot.severity == FindingSeverity.LOW
    assert lab.render(report) == original_html
    assert db.scalar(select(func.count()).select_from(ScanFindingSnapshot).where(
        ScanFindingSnapshot.scan_id == scan.id,
    )) == 1


def test_scan_report_labels_later_remediation_as_current_guidance(db, snapshot_lab):
    lab = snapshot_lab
    scan = lab.new_scan()
    finding = lab.persist([observation(evidence=("Original scan proof",))], scan)[0]
    report = lab.new_report(ReportType.TECHNICAL, scan)
    finding.llm_remediation = {
        "source": "llm", "summary": "Guidance generated after the scan",
        "remediation_steps": [],
    }
    db.commit()

    html = lab.render(report)
    assert "Guidance generated after the scan" in html
    assert "Current Remediation Summary (separate from the scan observation):" in html
    assert "Status at observation:</strong> open" in html
    assert severity_order(html) == ["low"]
    assert "Original scan proof" in html


def test_finding_snapshots_roll_back_with_the_observation_transaction(db, snapshot_lab):
    lab = snapshot_lab
    scan = lab.new_scan()
    scan_id = scan.id
    lab.persist([observation()], scan, commit=False)
    db.rollback()
    for model in (ScanFindingSnapshot, ScanFinding, FindingEvidence):
        assert db.scalar(select(func.count()).select_from(model).where(
            model.scan_id == scan_id,
        )) == 0
    assert db.scalar(select(func.count()).select_from(Finding).where(
        Finding.organization_id == lab.org_id,
    )) == 0
