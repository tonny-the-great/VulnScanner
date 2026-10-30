"""Report delivery: scoped, query-efficient generation and safe, audited downloads.

Findings, evidence and scan sightings are inserted directly; no scanner runs.
"""

import re
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.audit import AuditAction
from app.core.security_headers import REPORT_CSP
from app.database import SessionLocal
from app.main import app
from app.models import ScanFinding
from app.models.asset import Asset, AssetType
from app.models.audit import AuditLog
from app.models.finding import Finding, FindingConfidence, FindingEvidence, FindingSeverity
from app.models.report import Report
from app.models.scan import Scan, ScanStatus
from app.services.report_service import ReportService


@pytest.fixture(autouse=True)
def without_weasyprint(monkeypatch):
    # PDF export is unavailable unless a test installs a stand-in module.
    monkeypatch.setitem(sys.modules, "weasyprint", None)


class Lab:
    """An organization from the workflow fixture plus helpers that insert report data."""

    def __init__(self, db, client, prefix, template_scan_id):
        self.db = db
        self.client = client
        self.prefix = prefix
        self.org_id = uuid.UUID(prefix.rsplit("/", 1)[1])
        self.template = db.get(Scan, template_scan_id)

    def scan(self) -> uuid.UUID:
        scan = Scan(
            organization_id=self.org_id, authorization_id=self.template.authorization_id,
            profile_id=self.template.profile_id, created_by=self.template.created_by,
            status=ScanStatus.COMPLETED, completed_at=datetime.now(UTC),
        )
        self.db.add(scan)
        self.db.commit()
        return scan.id

    def asset(self, address) -> uuid.UUID:
        asset = Asset(
            organization_id=self.org_id, asset_type=AssetType.IPV4,
            ip_address=address, discovery_source="fixture",
        )
        self.db.add(asset)
        self.db.commit()
        return asset.id

    def finding(self, *, seen_in=(), evidence=(), asset_id=None, title=None,
                severity=FindingSeverity.MEDIUM, priority=5.0, seen_minutes_ago=None) -> uuid.UUID:
        """seen_in: scan ids in order (first and last become the scan references).
        evidence: (scan_id, content, minutes_ago[, evidence_type]) tuples.
        seen_minutes_ago: {scan_id: minutes_ago} sighting times (default: now)."""
        finding = Finding(
            organization_id=self.org_id, asset_id=asset_id,
            title=title or f"Delivery finding {uuid.uuid4().hex[:8]}",
            description="Fixture finding", source_tool="fixture", scanner_reference="fixture",
            confidence=FindingConfidence.CONFIRMED, severity=severity, priority_score=priority,
            fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
            first_seen_scan_id=seen_in[0] if seen_in else None,
            last_seen_scan_id=seen_in[-1] if seen_in else None,
        )
        self.db.add(finding)
        self.db.flush()
        now = datetime.now(UTC)
        for scan_id in seen_in:
            minutes_ago = (seen_minutes_ago or {}).get(scan_id, 0)
            self.db.add(
                ScanFinding(
                    scan_id=scan_id,
                    finding_id=finding.id,
                    seen_at=now - timedelta(minutes=minutes_ago),
                )
            )
        for scan_id, content, minutes_ago, *evidence_type in evidence:
            self.db.add(FindingEvidence(
                finding_id=finding.id, scan_id=scan_id,
                evidence_type=evidence_type[0] if evidence_type else "fixture",
                content=content, collected_at=now - timedelta(minutes=minutes_ago),
            ))
        self.db.commit()
        return finding.id

    def report(self, report_type, scan_id=None, title="Delivery report") -> uuid.UUID:
        body = {"report_type": report_type, "title": title}
        if scan_id:
            body["scan_id"] = str(scan_id)
        response = self.client.post(self.prefix + "/reports", json=body)
        assert response.status_code == 201, response.text
        return uuid.UUID(response.json()["id"])

    def render(self, report_type, scan_id=None) -> str:
        report_id = self.report(report_type, scan_id)
        with SessionLocal() as session:
            ReportService(session).build_report_files(report_id)
            return Path(session.get(Report, report_id).html_path).read_text(encoding="utf-8")

    def token(self, report_id) -> str:
        self.db.expire_all()
        return self.db.get(Report, report_id).access_token


@pytest.fixture
def lab(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    return Lab(db, client, prefix, launch_scan(workflow))


def card_value(html, title) -> int:
    match = re.search(re.escape(title) + r'</div>\s*<div class="card-value"[^>]*>(\d+)</div>', html)
    assert match, f"card {title!r} missing"
    return int(match.group(1))


def download_audits(db, report_id):
    db.expire_all()
    return list(db.scalars(select(AuditLog).where(
        AuditLog.object_id == str(report_id), AuditLog.action == AuditAction.REPORT_DOWNLOAD,
    )).all())


def assert_report_html_headers(response):
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["content-security-policy"] == REPORT_CSP
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


# ── Generation ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("report_type", ["executive", "technical"])
@pytest.mark.parametrize("scoped", [True, False], ids=["scan", "organization"])
def test_build_statement_count_does_not_grow_with_findings(lab, query_counter, report_type, scoped):
    earlier, current = lab.scan(), lab.scan()
    asset_id = lab.asset("192.168.10.20")

    def add_findings(count):
        for index in range(count):
            lab.finding(
                seen_in=(earlier, current),
                asset_id=asset_id,
                evidence=(
                    (earlier, f"old evidence {index}", 10),
                    (current, f"new evidence {index}", 1),
                ),
            )

    def statements_for_build():
        report_id = lab.report(report_type, current if scoped else None)
        query_counter.reset()
        with SessionLocal() as session:
            ReportService(session).build_report_files(report_id)
        return query_counter.count

    add_findings(3)
    with_three = statements_for_build()
    add_findings(17)
    with_twenty = statements_for_build()
    assert with_three == with_twenty, query_counter.statements


def test_scan_report_shows_that_scans_evidence_only(lab):
    s1, s2, s3 = lab.scan(), lab.scan(), lab.scan()
    lab.finding(
        seen_in=(s1, s2, s3), title="Evidence scoped finding",
        evidence=((s1, "evidence-from-scan-one", 20), (s2, "evidence-from-scan-two", 10)),
    )

    first = lab.render("technical", s1)
    assert "evidence-from-scan-one" in first
    assert "evidence-from-scan-two" not in first

    second = lab.render("technical", s2)
    assert "evidence-from-scan-two" in second
    assert "evidence-from-scan-one" not in second

    # S3 saw the finding but stored no evidence of its own (identical evidence is
    # not stored again): the newest evidence stands in for it.
    third = lab.render("technical", s3)
    assert "Evidence scoped finding" in third
    assert "evidence-from-scan-two" in third
    assert "evidence-from-scan-one" not in third

    overview = lab.render("technical")
    assert "evidence-from-scan-two" in overview
    assert "evidence-from-scan-one" not in overview


def test_scan_report_resolves_evidence_per_type_as_of_that_scan(lab):
    # The deduplicator skips per (finding, evidence type): S2 repeated S1's
    # request (two items of one observation, so not stored again) and stored
    # only its new response; S3 later stored new evidence of both types.
    s1, s2, s3 = lab.scan(), lab.scan(), lab.scan()
    lab.finding(
        seen_in=(s1, s2, s3), title="Per type evidence finding",
        seen_minutes_ago={s1: 30, s2: 20, s3: 10},
        evidence=(
            (s1, "request-from-s1-a", 30, "http_request"),
            (s1, "request-from-s1-b", 30, "http_request"),
            (s1, "response-from-s1", 30, "http_response"),
            (s2, "response-from-s2", 20, "http_response"),
            (s3, "request-from-s3", 10, "http_request"),
            (s3, "response-from-s3", 10, "http_response"),
        ),
    )

    second = lab.render("technical", s2)
    # Its own response, plus every row of the request observation it repeated.
    assert "response-from-s2" in second
    assert "request-from-s1-a" in second
    assert "request-from-s1-b" in second
    assert "response-from-s1" not in second
    # Evidence a later scan collected is never shown for an earlier one.
    assert "request-from-s3" not in second
    assert "response-from-s3" not in second

    overview = lab.render("technical")
    assert "request-from-s3" in overview
    assert "response-from-s3" in overview
    assert "request-from-s1-a" not in overview
    assert "response-from-s2" not in overview


def test_organization_report_shows_every_row_of_the_newest_observation(lab):
    s1, s2 = lab.scan(), lab.scan()
    lab.finding(
        seen_in=(s1, s2), seen_minutes_ago={s1: 20, s2: 10},
        evidence=(
            (s1, "older-item", 20, "nmap_script"),
            (s2, "newest-item-one", 10, "nmap_script"),
            (s2, "newest-item-two", 10, "nmap_script"),
        ),
    )

    overview = lab.render("technical")
    assert "newest-item-one" in overview
    assert "newest-item-two" in overview
    assert "older-item" not in overview


def test_finding_seen_in_a_middle_scan_appears_in_its_report(lab):
    s1, s2, s3 = lab.scan(), lab.scan(), lab.scan()
    lab.finding(seen_in=(s1, s2, s3), title="Recurring middle finding")
    lab.finding(seen_in=(s1, s3), title="Skipped middle finding")

    for report_type in ("executive", "technical"):
        html = lab.render(report_type, s2)
        assert "Recurring middle finding" in html
        assert "Skipped middle finding" not in html


def test_scan_report_counts_only_that_scans_assets(lab, db):
    s1, s2 = lab.scan(), lab.scan()
    first_asset, second_asset = lab.asset("192.168.10.21"), lab.asset("192.168.10.22")
    lab.asset("192.168.10.23")  # never affected by a finding
    lab.finding(seen_in=(s1,), asset_id=first_asset)
    lab.finding(seen_in=(s1,), asset_id=first_asset)
    lab.finding(seen_in=(s2,), asset_id=second_asset)

    html = lab.render("executive", s1)
    assert card_value(html, "Assets With Findings") == 1
    assert "Organization Assets" not in html

    org_assets = db.scalar(
        select(func.count()).select_from(Asset).where(Asset.organization_id == lab.org_id)
    )
    assert card_value(lab.render("executive"), "Organization Assets") == org_assets


def test_executive_totals_count_every_finding_but_list_the_top_ten(lab):
    scan_id = lab.scan()
    for index in range(12):
        lab.finding(
            seen_in=(scan_id,), title=f"Executive finding {index:02d}", priority=float(index),
            severity=FindingSeverity.CRITICAL if index < 3 else FindingSeverity.LOW,
        )

    for html in (lab.render("executive", scan_id), lab.render("executive")):
        assert card_value(html, "Total Findings") == 12
        assert card_value(html, "Critical & High") == 3
        assert html.count('<td><strong>Executive finding') == 10
        # Highest priority first; the two lowest-priority findings are left out.
        assert "Executive finding 11" in html
        assert "Executive finding 00" not in html
        assert "Executive finding 01" not in html


def test_html_is_committed_before_the_pdf_step(lab, monkeypatch):
    lab.finding(title="Committed before PDF")
    report_id = lab.report("technical")

    def failing_pdf(self, report):
        raise RuntimeError("PDF step failed")

    monkeypatch.setattr(ReportService, "build_pdf", failing_pdf)
    with SessionLocal() as session, pytest.raises(RuntimeError):
        ReportService(session).build_report_files(report_id)

    with SessionLocal() as session:
        html_path = session.get(Report, report_id).html_path
    assert html_path and Path(html_path).is_file()
    assert "Committed before PDF" in Path(html_path).read_text(encoding="utf-8")


# ── Delivery ──────────────────────────────────────────────────────────────────

def test_session_html_route_serves_members_with_report_headers(lab, db):
    lab.finding(title="Session delivered finding")
    report_id = lab.report("technical")
    url = lab.prefix + f"/reports/{report_id}/html"

    response = lab.client.get(url)
    assert response.status_code == 200, response.text
    assert "Session delivered finding" in response.text
    assert_report_html_headers(response)

    audits = download_audits(db, report_id)
    assert len(audits) == 1
    assert audits[0].actor_id is not None
    assert audits[0].metadata_["via"] == "session"
    assert audits[0].metadata_["format"] == "html"

    outsider = TestClient(app)
    tag = uuid.uuid4().hex
    email = f"outsider-{tag}@example.com"
    password = "OutsiderPassword123!"
    assert outsider.post("/api/v1/auth/register", json={
        "email": email, "password": password, "full_name": "Outsider",
    }).status_code == 201
    assert (
        outsider.post("/api/v1/auth/login", json={"email": email, "password": password}).status_code
        == 200
    )
    denied = outsider.get(url)
    assert denied.status_code in (403, 404)
    assert "Session delivered finding" not in denied.text
    assert len(download_audits(db, report_id)) == 1

    assert lab.client.get(lab.prefix + f"/reports/{uuid.uuid4()}/html").status_code == 404


def test_token_html_route_has_report_headers_and_anonymous_audit(lab, db):
    lab.finding(title="Token delivered finding")
    report_id = lab.report("executive")

    response = TestClient(app).get(f"/api/v1/reports/download/{lab.token(report_id)}/html")
    assert response.status_code == 200, response.text
    assert "Token delivered finding" in response.text
    assert_report_html_headers(response)

    audits = download_audits(db, report_id)
    assert len(audits) == 1
    assert audits[0].actor_id is None
    assert audits[0].metadata_ == {"via": "token", "format": "html"}


def test_pdf_route_fails_fast_without_rebuilding_when_pdf_export_is_missing(lab, db, monkeypatch):
    report_id = lab.report("technical")
    with SessionLocal() as session:
        ReportService(session).build_report_files(report_id)

    def no_rebuild(self, report):
        raise AssertionError("HTML must not be rebuilt")

    monkeypatch.setattr(ReportService, "build_html", no_rebuild)
    token_response = lab.client.get(f"/api/v1/reports/download/{lab.token(report_id)}/pdf")
    session_response = lab.client.get(lab.prefix + f"/reports/{report_id}/pdf")
    for response in (token_response, session_response):
        assert response.status_code == 404
        assert "PDF export is not installed on this server" in response.text
    assert download_audits(db, report_id) == []


def test_pdf_route_builds_once_and_serves_without_caching(lab, db, monkeypatch):
    renders = []

    class FakeDocument:
        def __init__(self, string, url_fetcher):
            renders.append(string)

        def write_pdf(self, target):
            Path(target).write_bytes(b"%PDF-1.4 fixture")

    monkeypatch.setitem(sys.modules, "weasyprint", SimpleNamespace(HTML=FakeDocument))
    lab.finding(title="PDF delivered finding")
    report_id = lab.report("technical", title='Quarterly "Q3" / review')

    for _ in range(2):
        response = lab.client.get(f"/api/v1/reports/download/{lab.token(report_id)}/pdf")
        assert response.status_code == 200, response.text
        assert response.content == b"%PDF-1.4 fixture"
        assert response.headers["content-type"] == "application/pdf"
        assert response.headers["cache-control"] == "no-store"
        assert (
            response.headers["content-disposition"]
            == 'attachment; filename="Report_Quarterly_Q3_review.pdf"'
        )

    assert len(renders) == 1
    assert "PDF delivered finding" in renders[0]
    audits = download_audits(db, report_id)
    assert [entry.metadata_ for entry in audits] == [{"via": "token", "format": "pdf"}] * 2


def test_report_list_honours_limit_and_offset(lab):
    created = {lab.report("executive", title=f"Paged report {index}") for index in range(3)}
    url = lab.prefix + "/reports"

    first_page = lab.client.get(url, params={"limit": 2})
    second_page = lab.client.get(url, params={"limit": 2, "offset": 2})
    assert first_page.status_code == second_page.status_code == 200
    first_ids = [item["id"] for item in first_page.json()]
    second_ids = [item["id"] for item in second_page.json()]
    assert len(first_ids) == 2 and len(second_ids) == 1
    assert {uuid.UUID(i) for i in first_ids + second_ids} == created
    assert lab.client.get(url, params={"limit": 0}).status_code == 422
    assert lab.client.get(url, params={"limit": 101}).status_code == 422
    assert lab.client.get(url, params={"offset": -1}).status_code == 422
