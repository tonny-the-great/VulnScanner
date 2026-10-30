"""Worker-side scan lifecycle: DNS checks, run planning, revocation, warnings and lookups.

Scanner stand-ins run local Python only; no network scan is performed.
"""

import ipaddress
import socket
import sys
import uuid
from datetime import UTC, datetime

from sqlalchemy import select, update

from app.core.exceptions import ValidationError
from app.database import SessionLocal
from app.models.authorization import ScopeAuthorization
from app.models.scan import Scan, ScanEvent, ScanProfile, ScanStatus
from app.scanning import orchestrator
from app.scanning.orchestrator import ScanOrchestrator


def _authorize(workflow, *targets: str) -> str:
    client, prefix, payload, _ = workflow
    response = client.post(
        prefix + "/authorizations",
        json={
            "title": "Runtime authorization",
            "signer_name": "Workflow Tester",
            "signer_email": "signer@example.com",
            "authorization_date": datetime.now(UTC).date().isoformat(),
            "targets": [{"value": t} for t in targets],
        },
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _profile(db, config: dict, **fields) -> str:
    profile = ScanProfile(
        name=f"runtime-{uuid.uuid4().hex}",
        display_name="Runtime fixture",
        config_json=config,
        **fields,
    )
    db.add(profile)
    db.commit()
    return str(profile.id)


def _scan(workflow, scan_id):
    client, prefix, _, _ = workflow
    response = client.get(prefix + f"/scans/{scan_id}")
    assert response.status_code == 200, response.text
    return response.json()


def _events(db, scan_id, event_type):
    db.expire_all()
    rows = db.scalars(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id, ScanEvent.event_type == event_type)
    ).all()
    return [row.payload for row in rows]


def _record_builds(monkeypatch, scanner, calls: list):
    def build_command(targets, config, output_file_base):
        calls.append((list(targets), dict(config), output_file_base))
        return [sys.executable, "-c", "pass"]

    monkeypatch.setattr(scanner, "build_command", build_command)


def _fake_dns(monkeypatch, answers: dict[str, str]):
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host not in answers:
            return real(host, port, *args, **kwargs)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (answers[host], 0))]

    monkeypatch.setattr("app.scanning.scope_gate.socket.getaddrinfo", getaddrinfo)


def test_hostname_resolving_to_blocked_address_fails_scan(workflow, launch_scan, db, monkeypatch):
    _, _, _, scanner = workflow
    answers = {"assets.example.com": "192.0.2.10"}
    _fake_dns(monkeypatch, answers)
    auth_id = _authorize(workflow, "assets.example.com")
    scan_id = launch_scan(workflow, authorization_id=auth_id, targets=["assets.example.com"])
    # The name now points at the metadata service (e.g. a DNS change after approval).
    answers["assets.example.com"] = "169.254.169.254"
    monkeypatch.setattr(
        scanner,
        "build_command",
        lambda *a: (_ for _ in ()).throw(AssertionError("scanner launched")),
    )
    ScanOrchestrator(db, scan_id).run_scan()
    result = _scan(workflow, scan_id)
    assert result["status"] == "failed"
    assert "assets.example.com" in result["error_message"]
    assert "169.254.169.254" in result["error_message"]


def test_nmap_runs_once_per_address_family(workflow, launch_scan, db, monkeypatch):
    _, _, _, scanner = workflow
    calls: list = []
    _record_builds(monkeypatch, scanner, calls)
    auth_id = _authorize(workflow, "192.168.10.10", "2001:db8::10")
    scan_id = launch_scan(
        workflow, authorization_id=auth_id, targets=["192.168.10.10", "2001:db8::10"]
    )
    ScanOrchestrator(db, scan_id).run_scan()
    assert _scan(workflow, scan_id)["status"] == "completed"
    assert len(calls) == 2
    families = [{ipaddress.ip_address(t).version for t in targets} for targets, _, _ in calls]
    assert families == [{4}, {6}]
    # Separate runs write separate output files.
    assert calls[0][2].endswith("nmap_out_0") and calls[1][2].endswith("nmap_out_1")


def test_testssl_skips_cidr_targets_with_warning(workflow, launch_scan, db, monkeypatch):
    testssl = type(workflow[3])()
    testssl.name = "testssl"
    calls: list = []
    _record_builds(monkeypatch, testssl, calls)
    monkeypatch.setitem(orchestrator.ADAPTER_REGISTRY, "testssl", testssl)
    profile_id = _profile(db, {"nmap": {"enabled": False}, "testssl": {"enabled": True}})
    auth_id = _authorize(workflow, "192.168.10.0/24")
    scan_id = launch_scan(workflow, authorization_id=auth_id, profile_id=profile_id,
                          targets=["192.168.10.0/24", "192.168.10.10"])
    ScanOrchestrator(db, scan_id).run_scan()
    assert _scan(workflow, scan_id)["status"] == "completed"
    assert [targets for targets, _, _ in calls] == [["192.168.10.10"]]
    warning = "testssl.sh cannot scan address ranges; skipped 192.168.10.0/24"
    finished = _events(db, scan_id, "tool_finished")
    assert finished[0]["tool"] == "testssl" and finished[0]["warnings"] == [warning]
    completed = _events(db, scan_id, "scan_completed")
    assert completed[0]["message"] == f"Scan completed with warnings: {warning}"


def test_testssl_with_only_ranges_is_an_empty_success(workflow, launch_scan, db, monkeypatch):
    testssl = type(workflow[3])()
    testssl.name = "testssl"
    monkeypatch.setattr(
        testssl,
        "build_command",
        lambda *a: (_ for _ in ()).throw(AssertionError("testssl launched")),
    )
    monkeypatch.setitem(orchestrator.ADAPTER_REGISTRY, "testssl", testssl)
    profile_id = _profile(db, {"nmap": {"enabled": False}, "testssl": {"enabled": True}})
    auth_id = _authorize(workflow, "192.168.10.0/24")
    scan_id = launch_scan(
        workflow, authorization_id=auth_id, profile_id=profile_id, targets=["192.168.10.0/24"]
    )
    ScanOrchestrator(db, scan_id).run_scan()
    assert _scan(workflow, scan_id)["status"] == "completed"
    finished = _events(db, scan_id, "tool_finished")
    assert finished[0]["exit_code"] == 0 and finished[0]["error"] is None
    assert finished[0]["warnings"] == [
        "testssl.sh cannot scan address ranges; skipped 192.168.10.0/24"
    ]


def test_revocation_during_scan_stops_later_tools(workflow, launch_scan, db, monkeypatch):
    client, prefix, payload, scanner = workflow
    nuclei = type(scanner)()
    nuclei.name = "nuclei"
    monkeypatch.setattr(
        nuclei, "build_command", lambda *a: (_ for _ in ()).throw(AssertionError("nuclei launched"))
    )
    monkeypatch.setitem(orchestrator.ADAPTER_REGISTRY, "nuclei", nuclei)
    profile_id = _profile(db, {"nmap": {"enabled": True}, "nuclei": {"enabled": True}})
    auth_id = uuid.UUID(payload["authorization_id"])
    original_build = scanner.build_command

    def revoke_then_build(targets, config, output_file_base):
        with SessionLocal() as other:
            other.execute(
                update(ScopeAuthorization)
                .where(ScopeAuthorization.id == auth_id)
                .values(is_revoked=True)
            )
            other.commit()
        return original_build(targets, config, output_file_base)

    monkeypatch.setattr(scanner, "build_command", revoke_then_build)
    scan_id = launch_scan(workflow, profile_id=profile_id)
    ScanOrchestrator(db, scan_id).run_scan()
    result = _scan(workflow, scan_id)
    assert result["status"] == "failed"
    assert "revoked" in result["error_message"]
    assert result["findings_count"] == 1  # the first tool's results are kept
    assert [e["tool"] for e in _events(db, scan_id, "tool_started")] == ["nmap"]
    findings = client.get(prefix + "/findings").json()
    assert [f["title"] for f in findings] == ["Local fixture vulnerability"]


def test_builder_validation_error_is_shown(workflow, launch_scan, db, monkeypatch):
    _, _, _, scanner = workflow

    def reject(targets, config, output_file_base):
        raise ValidationError("Port range 0-70000 is invalid")

    monkeypatch.setattr(scanner, "build_command", reject)
    scan_id = launch_scan(workflow)
    ScanOrchestrator(db, scan_id).run_scan()
    expected = "Scanner nmap could not run: Port range 0-70000 is invalid"
    assert _events(db, scan_id, "tool_finished")[0]["error"] == expected
    result = _scan(workflow, scan_id)
    assert result["status"] == "failed"
    assert result["error_message"] == expected


def test_started_at_is_set_when_validation_starts(workflow, launch_scan, db, monkeypatch):
    seen = []
    original = orchestrator.check_resolved_targets

    def observe(targets):
        with SessionLocal() as other:
            scan = other.get(Scan, scan_id)
            seen.append((scan.status, scan.started_at))
        return original(targets)

    monkeypatch.setattr(orchestrator, "check_resolved_targets", observe)
    scan_id = launch_scan(workflow)
    ScanOrchestrator(db, scan_id).run_scan()
    assert len(seen) == 1
    status, started_at = seen[0]
    assert status == ScanStatus.VALIDATING
    assert started_at is not None
    assert _scan(workflow, scan_id)["status"] == "completed"


def test_adapters_receive_intrusive_flag(workflow, launch_scan, db, monkeypatch):
    _, _, payload, scanner = workflow
    calls: list = []
    _record_builds(monkeypatch, scanner, calls)
    ScanOrchestrator(db, launch_scan(workflow)).run_scan()
    assert calls[-1][1]["is_intrusive"] is False
    profile = db.get(ScanProfile, uuid.UUID(payload["profile_id"]))
    profile.is_intrusive = True
    db.commit()
    ScanOrchestrator(db, launch_scan(workflow, intrusive_acknowledged=True)).run_scan()
    assert calls[-1][1]["is_intrusive"] is True
    db.expire_all()
    # The flag is added per run, never written into the stored profile.
    assert "is_intrusive" not in db.get(ScanProfile, uuid.UUID(payload["profile_id"])).config_json


def test_cancellation_polling_is_throttled(workflow, launch_scan, db, monkeypatch):
    _, _, _, scanner = workflow
    scanner.command = "import time; time.sleep(1)"
    scan_id = launch_scan(workflow)
    worker = ScanOrchestrator(db, scan_id)
    original_check = worker._cancel_requested
    checks = []
    marks = {}

    def counting_check():
        checks.append(1)
        return original_check()

    original_build, original_parse = scanner.build_command, scanner.parse_output

    def build_command(*args):
        marks["start"] = len(checks)
        return original_build(*args)

    def parse_output(*args):
        marks["end"] = len(checks)
        return original_parse(*args)

    monkeypatch.setattr(worker, "_cancel_requested", counting_check)
    monkeypatch.setattr(scanner, "build_command", build_command)
    monkeypatch.setattr(scanner, "parse_output", parse_output)
    worker.run_scan()
    assert _scan(workflow, scan_id)["status"] == "completed"
    assert marks["end"] - marks["start"] <= 3


def test_url_shaped_finding_address_links_to_asset(workflow, launch_scan, db, monkeypatch):
    client, prefix, _, scanner = workflow
    original_parse = scanner.parse_output

    def parse_output(*args):
        result = original_parse(*args)
        result.findings[0].target_address = "https://192.168.10.10:443/"
        return result

    monkeypatch.setattr(scanner, "parse_output", parse_output)
    ScanOrchestrator(db, launch_scan(workflow)).run_scan()
    findings = client.get(prefix + "/findings").json()
    assert len(findings) == 1
    assert findings[0]["asset_id"] and findings[0]["service_id"]


def test_finding_links_to_asset_from_an_earlier_scan(workflow, launch_scan, db, monkeypatch):
    client, prefix, _, scanner = workflow
    ScanOrchestrator(db, launch_scan(workflow)).run_scan()
    first = client.get(prefix + "/findings").json()
    original_parse = scanner.parse_output

    def parse_output(*args):
        # This run reports a finding but no asset record for its host.
        result = original_parse(*args)
        result.assets = []
        result.findings[0].title = "Second fixture vulnerability"
        result.findings[0].scanner_reference = "fixture-002"
        result.findings[0].target_address = "192.168.10.10:443"
        return result

    monkeypatch.setattr(scanner, "parse_output", parse_output)
    ScanOrchestrator(db, launch_scan(workflow)).run_scan()
    findings = {f["title"]: f for f in client.get(prefix + "/findings").json()}
    assert findings["Second fixture vulnerability"]["asset_id"] == first[0]["asset_id"]
    assert findings["Second fixture vulnerability"]["service_id"] == first[0]["service_id"]


def test_merged_runs_report_each_warning_once():
    notice = "OS detection skipped"
    runs = [
        orchestrator.RawScannerResult(
            tool_name="nmap", exit_code=0, execution_time_seconds=1, warnings=[notice]
        ),
        orchestrator.RawScannerResult(
            tool_name="nmap", exit_code=0, execution_time_seconds=2, warnings=[notice, "b"]
        ),
    ]
    merged = orchestrator._merge_results("nmap", runs, ["plan", notice])
    assert merged.warnings == ["plan", notice, "b"]
    assert merged.execution_time_seconds == 3
    single = orchestrator._merge_results("nmap", runs[:1], [notice])
    assert single.warnings == [notice]
