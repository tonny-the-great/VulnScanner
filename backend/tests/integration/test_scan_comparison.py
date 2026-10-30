"""Comparisons refuse missing or incompatible assessment coverage.

Scanner stand-ins execute local Python only; no network scan is performed.
"""

import copy
import uuid
from datetime import UTC, datetime

import pytest
from sqlalchemy import delete, select

from app.models.finding import Finding, FindingSeverity
from app.models.scan import Scan, ScanEvent, ScanProfile, ScanStatus, ScanTarget
from app.scanning.orchestrator import ScanOrchestrator


def _complete(workflow, launch_scan, db, **overrides):
    scan_id = launch_scan(workflow, **overrides)
    ScanOrchestrator(db, scan_id).run_scan()
    db.expire_all()
    assert db.get(Scan, scan_id).status == ScanStatus.COMPLETED
    return scan_id


def _compare(workflow, first, second):
    client, prefix, _, _ = workflow
    return client.get(prefix + f"/scans/{first}/compare/{second}")


def _event(db, scan_id, event_type):
    return db.scalars(select(ScanEvent).where(
        ScanEvent.scan_id == scan_id, ScanEvent.event_type == event_type,
    )).one()


def test_completed_comparison_reports_observed_absence_without_marking_fixed(
    workflow, launch_scan, db, monkeypatch,
):
    first = _complete(workflow, launch_scan, db)
    scanner = workflow[3]
    original_parse = scanner.parse_output

    def no_findings(*args):
        result = original_parse(*args)
        result.findings = []
        return result

    monkeypatch.setattr(scanner, "parse_output", no_findings)
    second = _complete(workflow, launch_scan, db)
    response = _compare(workflow, first, second)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["resolved_findings_count"] == 1
    assert body["new_findings_count"] == body["persistent_findings_count"] == 0
    assert "not observed" in body["comparison_note"]
    assert "does not verify" in body["comparison_note"]
    db.expire_all()
    finding = db.get(Finding, uuid.UUID(body["resolved_findings"][0]["id"]))
    assert finding.status.value == "open"


@pytest.mark.parametrize(
    "status", [status for status in ScanStatus if status != ScanStatus.COMPLETED],
)
def test_comparison_refuses_unfinished_failed_and_partial_scans(workflow, launch_scan, db, status):
    first = _complete(workflow, launch_scan, db)
    second = launch_scan(workflow)
    db.get(Scan, second).status = status
    db.commit()
    for base, compared in ((first, second), (second, first)):
        response = _compare(workflow, base, compared)
        assert response.status_code == 409, response.text
        assert "completed successfully" in response.json()["detail"]
        assert "resolved_findings" not in response.json()


@pytest.mark.parametrize("change", ["empty", "unverified", "different"])
def test_comparison_requires_matching_nonempty_verified_targets(workflow, launch_scan, db, change):
    first = _complete(workflow, launch_scan, db)
    second = _complete(workflow, launch_scan, db)
    target = db.scalars(select(ScanTarget).where(ScanTarget.scan_id == second)).one()
    if change == "empty":
        db.delete(target)
    elif change == "unverified":
        target.scope_verified = False
    else:
        target.target_value = "192.168.10.11"
    db.commit()
    response = _compare(workflow, first, second)
    assert response.status_code == 409, response.text
    assert "target" in response.json()["detail"]


def test_comparison_matches_normalized_target_sets_independent_of_order(workflow, launch_scan, db):
    client, prefix, _, _ = workflow
    authorization = client.post(prefix + "/authorizations", json={
        "title": "Comparison targets", "signer_name": "Fixture Tester",
        "signer_email": "signer@example.com",
        "authorization_date": datetime.now(UTC).date().isoformat(),
        "targets": [{"value": "192.168.10.10"}, {"value": "2001:db8::10"}],
    })
    assert authorization.status_code == 201, authorization.text
    overrides = {"authorization_id": authorization.json()["id"]}
    first = _complete(
        workflow, launch_scan, db, **overrides, targets=["192.168.10.10", "2001:db8::10"],
    )
    second = _complete(
        workflow, launch_scan, db, **overrides,
        targets=["2001:0db8:0:0:0:0:0:10", "192.168.10.10", "192.168.10.10"],
    )
    response = _compare(workflow, first, second)
    assert response.status_code == 200, response.text
    assert response.json()["persistent_findings_count"] == 1


def test_comparison_refuses_profile_changes_even_when_profile_id_matches(workflow, launch_scan, db):
    first = _complete(workflow, launch_scan, db)
    profile = db.get(ScanProfile, uuid.UUID(workflow[2]["profile_id"]))
    profile.config_json = {"nmap": {"enabled": True, "top_ports": 10}}
    db.commit()
    second = _complete(workflow, launch_scan, db)
    response = _compare(workflow, first, second)
    assert response.status_code == 409, response.text
    assert "matching recorded scanner configurations" in response.json()["detail"]
    plan = _event(db, first, "execution_plan").payload
    assert plan["config"] == {"nmap": {"enabled": True}, "is_intrusive": False}


def test_comparison_uses_execution_config_even_after_profile_is_changed(workflow, launch_scan, db):
    first = _complete(workflow, launch_scan, db)
    second = _complete(workflow, launch_scan, db)
    profile = db.get(ScanProfile, uuid.UUID(workflow[2]["profile_id"]))
    profile.config_json = {"nmap": {"enabled": False}, "nuclei": {"enabled": True}}
    db.commit()
    response = _compare(workflow, first, second)
    assert response.status_code == 200, response.text


def test_comparison_summaries_use_each_scans_observation_after_live_values_change(
    workflow, launch_scan, db, monkeypatch,
):
    scanner = workflow[3]
    original_parse = scanner.parse_output
    compared = False

    def observations(*args):
        result = original_parse(*args)
        result.findings[0].severity = FindingSeverity.LOW if compared else FindingSeverity.HIGH
        extra = copy.deepcopy(result.findings[0])
        extra.scanner_reference = "new-only" if compared else "base-only"
        extra.title = "New only fixture" if compared else "Base only fixture"
        extra.severity = FindingSeverity.MEDIUM if compared else FindingSeverity.HIGH
        result.findings.append(extra)
        return result

    monkeypatch.setattr(scanner, "parse_output", observations)
    first = _complete(workflow, launch_scan, db)
    compared = True
    second = _complete(workflow, launch_scan, db)
    org_id = uuid.UUID(workflow[1].split("/")[-1])
    findings = db.scalars(select(Finding).where(Finding.organization_id == org_id)).all()
    assert len(findings) == 3
    original_fingerprints = {finding.title: finding.fingerprint for finding in findings}
    for finding in findings:
        finding.severity = FindingSeverity.CRITICAL
        finding.title = "Later live finding"
        finding.fingerprint = uuid.uuid4().hex
    db.commit()

    response = _compare(workflow, first, second)
    assert response.status_code == 200, response.text
    body = response.json()
    for category, title, severity in (
        ("resolved_findings", "Base only fixture", "high"),
        ("new_findings", "New only fixture", "medium"),
        ("persistent_findings", "Local fixture vulnerability", "low"),
    ):
        assert len(body[category]) == 1
        assert body[category][0]["title"] == title
        assert body[category][0]["severity"] == severity
        assert body[category][0]["fingerprint"] == original_fingerprints[title]


@pytest.mark.parametrize("change", [
    "legacy", "missing_finish", "missing_start", "duplicate_finish", "extra_tool",
    "warning", "error", "failed_tool", "changed_plan_targets", "empty_tools", "bad_version",
])
def test_comparison_refuses_unverifiable_or_incomplete_execution_coverage(
    workflow, launch_scan, db, change,
):
    first = _complete(workflow, launch_scan, db)
    second = _complete(workflow, launch_scan, db)
    if change == "legacy":
        db.execute(delete(ScanEvent).where(
            ScanEvent.scan_id == second, ScanEvent.event_type == "execution_plan",
        ))
    elif change in ("missing_finish", "missing_start"):
        event_type = "tool_finished" if change == "missing_finish" else "tool_started"
        db.delete(_event(db, second, event_type))
    elif change in ("duplicate_finish", "extra_tool"):
        payload = copy.deepcopy(_event(db, second, "tool_finished").payload)
        if change == "extra_tool":
            payload["tool"] = "nuclei"
        db.add(ScanEvent(scan_id=second, event_type="tool_finished", payload=payload))
    elif change in ("warning", "error", "failed_tool"):
        event = _event(db, second, "tool_finished")
        payload = copy.deepcopy(event.payload)
        if change == "warning":
            payload["warnings"] = ["Target was skipped"]
        elif change == "error":
            payload["error"] = "Partial scanner output"
        else:
            payload["exit_code"] = 1
        event.payload = payload
    else:
        event = _event(db, second, "execution_plan")
        payload = copy.deepcopy(event.payload)
        if change == "changed_plan_targets":
            payload["targets"][0]["value"] = "192.168.10.11"
        elif change == "empty_tools":
            payload["tools"] = []
        else:
            payload["version"] = 999
        event.payload = payload
    db.commit()
    response = _compare(workflow, first, second)
    assert response.status_code == 409, response.text
    assert "resolved_findings" not in response.json()
