"""Exercise API authorization, orchestration, normalization, and report downloads.

Scanner stand-ins run local Python only; no network scan is performed. The
LocalScanner stand-in and the workflow fixture live in conftest.py.
"""

import sys
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.main import app
from app.models.report import Report
from app.models.scan import Scan, ScanEvent, ScanProfile, ScanStatus
from app.scanning.adapters import ADAPTER_REGISTRY
from app.scanning.adapters.nmap.adapter import NmapAdapter
from app.scanning.orchestrator import ScanOrchestrator
from app.services.report_service import ReportService


def start_scan(workflow):
    client, prefix, payload, scanner = workflow
    response = client.post(prefix + "/scans", json=payload)
    assert response.status_code == 201, response.text
    return uuid.UUID(response.json()["id"])


def test_scan_to_report_and_scope_rejection(workflow, db):
    client, prefix, payload, scanner = workflow
    denied = client.post(prefix + "/scans", json={**payload, "targets": ["192.168.10.11"]})
    assert denied.status_code == 400
    scan_id = start_scan(workflow)
    ScanOrchestrator(db, scan_id).run_scan()
    response = client.get(prefix + f"/scans/{scan_id}")
    assert response.json()["status"] == "completed", response.text
    assert response.json()["findings_count"] == 1
    findings = client.get(prefix + "/findings").json()
    assert len(findings) == 1
    assert findings[0]["asset_id"] and findings[0]["service_id"]
    assert findings[0]["priority_score"] > 0
    audit = client.get(prefix + "/audit-log", params={"resource_type": "scan"})
    assert audit.status_code == 200, audit.text
    assert any(entry["resource_id"] == str(scan_id) for entry in audit.json())
    assert all(entry["actor_email"] for entry in audit.json())
    for report_type in ("technical", "executive"):
        response = client.post(
            prefix + "/reports",
            json={"scan_id": str(scan_id), "report_type": report_type, "title": "Workflow Report"},
        )
        assert response.status_code == 201, response.text
        report = db.get(Report, uuid.UUID(response.json()["id"]))
        ReportService(db).build_report_files(report.id)
        html = client.get(f"/api/v1/reports/download/{report.access_token}/html")
        assert html.status_code == 200
        assert "Local fixture vulnerability" in html.text
        assert "Scan status:</strong> completed" in html.text
        assert "<script>untrusted</script>" not in html.text
    # Repeat delivery of a completed job must not create duplicate findings/events.
    event_count = len(db.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan_id)).all())
    ScanOrchestrator(db, scan_id).run_scan()
    assert (
        len(db.scalars(select(ScanEvent).where(ScanEvent.scan_id == scan_id)).all()) == event_count
    )
    report.token_expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db.commit()
    assert client.get(f"/api/v1/reports/download/{report.access_token}/html").status_code == 401


@pytest.mark.parametrize("failure", ["missing", "exit", "parse", "timeout"])
def test_failed_scanners_never_report_success(workflow, db, monkeypatch, failure):
    client, prefix, payload, scanner = workflow
    if failure == "missing":
        scanner.available = False
    elif failure == "exit":
        scanner.command = "import sys; sys.exit(2)"
    elif failure == "parse":
        scanner.parser_error = "invalid output"
    else:
        scanner.command = "import time; time.sleep(30)"
        monkeypatch.setattr(get_settings(), "SCAN_TIMEOUT", 1)
    scan_id = start_scan(workflow)
    ScanOrchestrator(db, scan_id).run_scan()
    result = client.get(prefix + f"/scans/{scan_id}").json()
    assert result["status"] == ("timed_out" if failure == "timeout" else "failed")
    assert result["completed_at"] is None
    assert result["error_message"]
    if failure != "missing":
        assert result["findings_count"] == 1  # usable partial data is retained
    response = client.post(
        prefix + "/reports",
        json={"scan_id": str(scan_id), "report_type": "executive", "title": "Partial report"},
    )
    assert response.status_code == 201
    report = db.get(Report, uuid.UUID(response.json()["id"]))
    html = client.get(f"/api/v1/reports/download/{report.access_token}/html")
    assert html.status_code == 200
    assert "Incomplete assessment" in html.text


def test_cancel_before_worker_does_not_launch(workflow, db, monkeypatch):
    client, prefix, payload, scanner = workflow
    monkeypatch.setattr(
        scanner, "build_command", lambda *args: pytest.fail("Cancelled scan launched a process")
    )
    scan_id = start_scan(workflow)
    assert client.post(prefix + f"/scans/{scan_id}/cancel").status_code == 200
    ScanOrchestrator(db, scan_id).run_scan()
    result = client.get(prefix + f"/scans/{scan_id}").json()
    assert result["status"] == "cancelled"
    assert result["started_at"] is None
    assert result["cancelled_at"] is not None


def test_cancel_running_process(workflow, db, monkeypatch):
    client, prefix, payload, scanner = workflow
    scanner.command = "import time; time.sleep(30)"
    scan_id = start_scan(workflow)
    worker = ScanOrchestrator(db, scan_id)
    original_check = worker._cancel_requested
    original_stop = worker._stop_process
    stopped = []

    def stop_process(proc):
        original_stop(proc)
        stopped.append(proc.returncode)

    monkeypatch.setattr(worker, "_stop_process", stop_process)
    requested = False

    def request_during_execution():
        nonlocal requested
        scan = worker._scan()
        if scan.status == ScanStatus.RUNNING and not requested:
            # First RUNNING check is before tool launch; second is inside process polling.
            requested = True
            return False
        if scan.status == ScanStatus.RUNNING and requested:
            with SessionLocal() as other:
                current = other.get(Scan, scan_id)
                current.status = ScanStatus.CANCEL_REQUESTED
                other.commit()
        return original_check()

    monkeypatch.setattr(worker, "_cancel_requested", request_during_execution)
    worker.run_scan()
    result = client.get(prefix + f"/scans/{scan_id}").json()
    assert result["status"] == "cancelled"
    assert result["cancelled_at"] is not None
    assert result["findings_count"] == 1
    assert stopped and stopped[0] is not None and stopped[0] != 0


def test_report_cannot_reference_another_organization(workflow, db):
    client, prefix, payload, scanner = workflow
    scan_id = start_scan(workflow)
    tag = uuid.uuid4().hex
    response = client.post(
        "/api/v1/organizations", json={"name": f"Other {tag}", "slug": f"other-{tag}"}
    )
    other_prefix = f"/api/v1/organizations/{response.json()['id']}"
    response = client.post(
        other_prefix + "/reports",
        json={"scan_id": str(scan_id), "report_type": "technical", "title": "Wrong org"},
    )
    assert response.status_code == 404


def test_real_nmap_parser_through_api_report(workflow, db, monkeypatch):
    xml = """<nmaprun><host><status state="up"/><address addr="192.168.10.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/>
    <script id="fixture-vuln"
      output="VULNERABLE CVE-2025-12345 &lt;script&gt;fixture&lt;/script&gt;"/>
    </port></ports></host></nmaprun>"""

    class FixtureNmap(NmapAdapter):
        def is_available(self):
            return True

        def build_command(self, targets, config, output_file_base):
            return [
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; "
                "Path(sys.argv[1]).write_text(sys.argv[2], encoding='utf-8')",
                output_file_base + ".xml",
                xml,
            ]

    monkeypatch.setitem(ADAPTER_REGISTRY, "nmap", FixtureNmap())
    client, prefix, payload, scanner = workflow
    scan_id = start_scan(workflow)
    ScanOrchestrator(db, scan_id).run_scan()
    result = client.get(prefix + f"/scans/{scan_id}").json()
    assert result["status"] == "completed"
    findings = client.get(prefix + "/findings").json()
    assert len(findings) == 1
    assert findings[0]["cve_ids"] == ["CVE-2025-12345"]
    assert findings[0]["confidence"] == "confirmed"
    # Evidence is part of the finding detail, not the list view.
    detail = client.get(prefix + f"/findings/{findings[0]['id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["evidence"][0]["scan_id"] == str(scan_id)
    response = client.post(
        prefix + "/reports",
        json={"scan_id": str(scan_id), "report_type": "technical", "title": "Parser report"},
    )
    assert response.status_code == 201
    report = db.get(Report, uuid.UUID(response.json()["id"]))
    html = client.get(f"/api/v1/reports/download/{report.access_token}/html")
    assert html.status_code == 200
    assert "CVE-2025-12345" in html.text
    assert "&lt;script&gt;fixture&lt;/script&gt;" in html.text
    assert "<script>fixture</script>" not in html.text


def test_queue_failure_marks_scan_failed(workflow, db, monkeypatch):
    def unavailable(*args):
        raise RuntimeError("Queue unavailable")

    monkeypatch.setattr("app.services.scan_service.enqueue_job", unavailable)
    client, prefix, payload, scanner = workflow
    response = client.post(prefix + "/scans", json=payload)
    assert response.status_code == 409
    scans = client.get(prefix + "/scans").json()
    assert len(scans) == 1
    assert scans[0]["status"] == "failed"


def test_target_limit_and_profile_ownership(workflow, db, monkeypatch):
    client, prefix, payload, scanner = workflow
    monkeypatch.setattr(get_settings(), "MAX_TARGETS_PER_SCAN", 1)
    response = client.post(prefix + "/scans", json={**payload, "targets": payload["targets"] * 2})
    assert response.status_code == 422
    tag = uuid.uuid4().hex
    other = client.post(
        "/api/v1/organizations", json={"name": f"Profile {tag}", "slug": f"profile-{tag}"}
    ).json()
    profile = db.get(ScanProfile, uuid.UUID(payload["profile_id"]))
    profile.organization_id = uuid.UUID(other["id"])
    db.commit()
    assert client.post(prefix + "/scans", json=payload).status_code == 404


def test_intrusive_profile_requires_admin(workflow, db):
    client, prefix, payload, scanner = workflow
    profile = db.get(ScanProfile, uuid.UUID(payload["profile_id"]))
    profile.is_intrusive = True
    db.commit()
    payload = {**payload, "intrusive_acknowledged": True}
    with TestClient(app) as analyst:
        email = f"analyst-{uuid.uuid4().hex}@example.com"
        assert (
            analyst.post(
                "/api/v1/auth/register",
                json={
                    "email": email,
                    "password": "AnalystPassword123!",
                    "full_name": "Analyst Tester",
                },
            ).status_code
            == 201
        )
        added = client.post(prefix + "/members", json={"email": email, "role": "analyst"})
        assert added.status_code == 201, added.text
        assert (
            analyst.post(
                "/api/v1/auth/login", json={"email": email, "password": "AnalystPassword123!"}
            ).status_code
            == 200
        )
        assert analyst.post(prefix + "/scans", json=payload).status_code == 403
