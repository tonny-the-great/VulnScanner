"""Scan and authorization API behaviour: concurrency, revocation, list loading, comparison."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.config import get_settings
from app.core.audit import AuditAction
from app.models.audit import AuditLog
from app.models.authorization import TargetType
from app.models.finding import Finding, FindingConfidence, FindingSeverity, ScanFinding
from app.models.scan import Scan, ScanEvent, ScanStatus, ScanTarget
from app.scanning.orchestrator import ScanOrchestrator


def _create_org(client, db, payload, *, max_concurrent_scans):
    """
    Create an organization (via the API) with its own authorization;
    return (prefix, payload, auth).
    """
    tag = uuid.uuid4().hex
    response = client.post(
        "/api/v1/organizations",
        json={
            "name": f"Limited {tag}",
            "slug": f"limited-{tag}",
            "max_concurrent_scans": max_concurrent_scans,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["max_concurrent_scans"] == max_concurrent_scans
    prefix = f"/api/v1/organizations/{response.json()['id']}"
    auth = client.post(
        prefix + "/authorizations",
        json={
            "title": "Limited authorization",
            "signer_name": "Workflow Tester",
            "signer_email": "signer@example.com",
            "authorization_date": datetime.now(UTC).date().isoformat(),
            "targets": [{"value": "192.168.10.10"}],
        },
    )
    assert auth.status_code == 201, auth.text
    return prefix, {**payload, "authorization_id": auth.json()["id"]}, auth.json()


def _insert_scan(
    db, org_id, auth, profile_id, *, status=ScanStatus.COMPLETED, queued_at=None, started_at=None
):
    scan = Scan(
        organization_id=uuid.UUID(str(org_id)),
        authorization_id=uuid.UUID(auth["id"]),
        profile_id=uuid.UUID(str(profile_id)),
        created_by=uuid.UUID(auth["created_by"]),
        status=status,
        queued_at=queued_at or datetime.now(UTC),
        started_at=started_at,
    )
    db.add(scan)
    db.flush()
    db.add(
        ScanTarget(
            scan_id=scan.id,
            target_value="192.168.10.10",
            target_type=TargetType.IPV4,
            scope_verified=True,
        )
    )
    db.commit()
    return scan.id


def _workflow_auth(client, prefix, payload):
    response = client.get(prefix + f"/authorizations/{payload['authorization_id']}")
    assert response.status_code == 200, response.text
    return response.json()


def test_stale_running_scan_does_not_block_concurrency_slot(workflow, db):
    client, _prefix, payload, _scanner = workflow
    prefix, limited_payload, auth = _create_org(client, db, payload, max_concurrent_scans=1)
    settings = get_settings()
    long_ago = datetime.now(UTC) - timedelta(
        seconds=settings.scan_timeout_seconds + settings.SCAN_STALE_GRACE_SECONDS + 60
    )
    stale_id = _insert_scan(
        db, auth["organization_id"], auth, payload["profile_id"],
        status=ScanStatus.RUNNING, queued_at=long_ago, started_at=long_ago,
    )

    response = client.post(prefix + "/scans", json=limited_payload)
    assert response.status_code == 201, response.text

    db.expire_all()
    stale = db.get(Scan, stale_id)
    assert stale.status == ScanStatus.FAILED
    assert stale.error_message

    # The limit itself still applies to live scans.
    blocked = client.post(prefix + "/scans", json=limited_payload)
    assert blocked.status_code == 409, blocked.text


def test_revoking_authorization_cancels_its_unfinished_scans(workflow, launch_scan, db):
    client, prefix, payload, _scanner = workflow
    scan_id = launch_scan(workflow)
    assert client.get(prefix + f"/scans/{scan_id}").json()["status"] == "queued"

    revoked = client.delete(prefix + f"/authorizations/{payload['authorization_id']}")
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["is_revoked"] is True
    assert client.get(prefix + f"/scans/{scan_id}").json()["status"] == "cancel_requested"

    audit = client.get(prefix + "/audit-log", params={"action": AuditAction.AUTHZ_REVOKE})
    assert audit.status_code == 200, audit.text
    entries = [e for e in audit.json() if e["resource_id"] == payload["authorization_id"]]
    assert len(entries) == 1
    assert entries[0]["metadata_sanitized"]["cancelled_scan_ids"] == [str(scan_id)]

    db.expire_all()
    ScanOrchestrator(db, scan_id).run_scan()
    result = client.get(prefix + f"/scans/{scan_id}").json()
    assert result["status"] == "cancelled"
    assert result["started_at"] is None

    # Revoking again is a no-op and does not audit twice.
    assert (
        client.delete(prefix + f"/authorizations/{payload['authorization_id']}").status_code == 200
    )
    audit = client.get(prefix + "/audit-log", params={"action": AuditAction.AUTHZ_REVOKE}).json()
    assert len([e for e in audit if e["resource_id"] == payload["authorization_id"]]) == 1


def test_finished_scans_are_not_touched_by_revocation(workflow, db):
    client, prefix, payload, _scanner = workflow
    auth = _workflow_auth(client, prefix, payload)
    done_id = _insert_scan(db, auth["organization_id"], auth, payload["profile_id"])
    assert (
        client.delete(prefix + f"/authorizations/{payload['authorization_id']}").status_code == 200
    )
    db.expire_all()
    assert db.get(Scan, done_id).status == ScanStatus.COMPLETED


def test_scan_list_query_count_does_not_grow_with_rows(workflow, db, query_counter):
    client, prefix, payload, _scanner = workflow
    auth = _workflow_auth(client, prefix, payload)
    for _ in range(2):
        _insert_scan(db, auth["organization_id"], auth, payload["profile_id"])
    db.close()  # the test session must not hold a connection or transaction

    assert client.get(prefix + "/scans").status_code == 200  # warm-up
    query_counter.reset()
    response = client.get(prefix + "/scans")
    assert response.status_code == 200
    assert len(response.json()) == 2
    assert all(len(s["targets"]) == 1 for s in response.json())
    few = query_counter.count

    for _ in range(8):
        _insert_scan(db, auth["organization_id"], auth, payload["profile_id"])
    db.close()
    query_counter.reset()
    response = client.get(prefix + "/scans")
    assert response.status_code == 200
    assert len(response.json()) == 10
    assert all(len(s["targets"]) == 1 for s in response.json())
    assert query_counter.count == few


def test_authorization_list_limit_and_offset(workflow):
    client, prefix, payload, _scanner = workflow
    for index in range(3):
        response = client.post(
            prefix + "/authorizations",
            json={
                "title": f"Extra authorization {index}",
                "signer_name": "Workflow Tester",
                "signer_email": "signer@example.com",
                "authorization_date": datetime.now(UTC).date().isoformat(),
                "targets": [{"value": f"10.0.0.{index + 1}"}],
            },
        )
        assert response.status_code == 201, response.text

    everything = client.get(prefix + "/authorizations")
    assert everything.status_code == 200
    all_ids = [a["id"] for a in everything.json()]
    assert len(all_ids) == 4
    assert all(len(a["authorized_targets"]) == 1 for a in everything.json())
    created = [a["created_at"] for a in everything.json()]
    assert created == sorted(created, reverse=True)

    first = client.get(prefix + "/authorizations", params={"limit": 2})
    second = client.get(prefix + "/authorizations", params={"limit": 2, "offset": 2})
    assert [a["id"] for a in first.json()] == all_ids[:2]
    assert [a["id"] for a in second.json()] == all_ids[2:]
    assert client.get(prefix + "/authorizations", params={"offset": 4}).json() == []

    assert client.get(prefix + "/authorizations", params={"limit": 0}).status_code == 422
    assert client.get(prefix + "/authorizations", params={"limit": 101}).status_code == 422
    assert client.get(prefix + "/authorizations", params={"offset": -1}).status_code == 422


def _finding(org_id, first_scan_id, last_scan_id, fingerprint):
    return Finding(
        organization_id=org_id, title=f"Finding {fingerprint}", source_tool="nmap",
        confidence=FindingConfidence.CONFIRMED, severity=FindingSeverity.HIGH,
        fingerprint=fingerprint, first_seen_scan_id=first_scan_id, last_seen_scan_id=last_scan_id,
    )


def test_compare_uses_per_scan_sightings(workflow, db):
    client, prefix, payload, _scanner = workflow
    auth = _workflow_auth(client, prefix, payload)
    org_id = uuid.UUID(auth["organization_id"])
    s1, s2, s3 = (_insert_scan(db, org_id, auth, payload["profile_id"]) for _ in range(3))
    for scan_id in (s1, s2, s3):
        db.add_all([
            ScanEvent(scan_id=scan_id, event_type="execution_plan", payload={
                "version": 1,
                "config": {"nmap": {"enabled": True}, "is_intrusive": False},
                "tools": ["nmap"],
                "targets": [{"type": "ipv4", "value": "192.168.10.10"}],
            }),
            ScanEvent(scan_id=scan_id, event_type="tool_started", payload={"tool": "nmap"}),
            ScanEvent(scan_id=scan_id, event_type="tool_finished", payload={
                "tool": "nmap", "exit_code": 0, "error": None, "warnings": [],
            }),
        ])

    persistent = _finding(org_id, s1, s3, uuid.uuid4().hex)  # seen in S1, S2 and S3
    resolved = _finding(org_id, s1, s1, uuid.uuid4().hex)    # seen only in S1
    new = _finding(org_id, s2, s3, uuid.uuid4().hex)         # seen in S2 and S3
    db.add_all([persistent, resolved, new])
    db.flush()
    db.add_all([
        ScanFinding(scan_id=s1, finding_id=persistent.id),
        ScanFinding(scan_id=s2, finding_id=persistent.id),
        ScanFinding(scan_id=s3, finding_id=persistent.id),
        ScanFinding(scan_id=s1, finding_id=resolved.id),
        ScanFinding(scan_id=s2, finding_id=new.id),
        ScanFinding(scan_id=s3, finding_id=new.id),
    ])
    db.commit()

    first = client.get(prefix + f"/scans/{s1}/compare/{s2}")
    assert first.status_code == 200, first.text
    body = first.json()
    assert [f["fingerprint"] for f in body["persistent_findings"]] == [persistent.fingerprint]
    assert [f["fingerprint"] for f in body["resolved_findings"]] == [resolved.fingerprint]
    assert [f["fingerprint"] for f in body["new_findings"]] == [new.fingerprint]
    assert (
        body["new_findings_count"],
        body["resolved_findings_count"],
        body["persistent_findings_count"],
    ) == (1, 1, 1)

    second = client.get(prefix + f"/scans/{s2}/compare/{s3}").json()
    assert sorted(f["fingerprint"] for f in second["persistent_findings"]) == sorted(
        [persistent.fingerprint, new.fingerprint]
    )
    assert second["new_findings_count"] == 0
    assert second["resolved_findings_count"] == 0


def test_scan_create_is_audited_exactly_once(workflow, launch_scan, db):
    scan_ids = [launch_scan(workflow), launch_scan(workflow)]
    db.expire_all()
    for scan_id in scan_ids:
        entries = db.scalars(select(AuditLog).where(
            AuditLog.action == AuditAction.SCAN_CREATE, AuditLog.object_id == str(scan_id),
        )).all()
        assert len(entries) == 1
        assert entries[0].metadata_["targets"] == ["192.168.10.10"]
        assert db.get(Scan, scan_id).rq_job_id == "test-job"
