"""Findings and assets API: slim list views, query counts, triage consistency and asset edits."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from app.core.audit import AuditAction
from app.models.asset import Asset, AssetType
from app.models.audit import AuditLog
from app.models.finding import Finding, FindingConfidence, FindingEvidence, FindingSeverity
from app.scanning.orchestrator import ScanOrchestrator


def org_id_of(prefix):
    return uuid.UUID(prefix.rsplit("/", 1)[1])


def add_finding(db, org_id, scan_id, *, priority=5.0, asset_id=None, evidence_times=(None,)):
    finding = Finding(
        organization_id=org_id, asset_id=asset_id, title=f"Finding {uuid.uuid4().hex[:8]}",
        description="Fixture finding", source_tool="nmap", scanner_reference="fixture",
        confidence=FindingConfidence.CONFIRMED, severity=FindingSeverity.MEDIUM,
        priority_score=priority, fingerprint=uuid.uuid4().hex + uuid.uuid4().hex,
    )
    db.add(finding)
    db.flush()
    for index, collected_at in enumerate(evidence_times):
        evidence = FindingEvidence(
            finding_id=finding.id, scan_id=scan_id, evidence_type="fixture",
            content=f"evidence {index}",
        )
        if collected_at is not None:
            evidence.collected_at = collected_at
        db.add(evidence)
    db.commit()
    return finding.id


def audit_rows(db, object_id):
    db.expire_all()
    return list(db.scalars(
        select(AuditLog).where(AuditLog.object_id == str(object_id)).order_by(AuditLog.timestamp)
    ).all())


def parse_time(value):
    return datetime.fromisoformat(value)


def test_list_is_slim_and_detail_has_evidence(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    scan_id = launch_scan(workflow)
    ScanOrchestrator(db, scan_id).run_scan()

    items = client.get(prefix + "/findings").json()
    assert len(items) == 1
    assert "evidence" not in items[0]
    assert "remediation_notes" not in items[0]
    assert "llm_remediation" in items[0] and "assigned_to" in items[0]

    detail = client.get(prefix + f"/findings/{items[0]['id']}").json()
    assert detail["evidence"][0]["content"] == "<script>evidence</script>"
    assert detail["remediation_notes"] == []

    asset_items = client.get(prefix + f"/assets/{items[0]['asset_id']}/findings").json()
    assert [item["id"] for item in asset_items] == [items[0]["id"]]
    assert "evidence" not in asset_items[0]

    # Search is a case-insensitive substring match; LIKE wildcards match literally.
    assert len(client.get(prefix + "/findings", params={"search": "FIXTURE vuln"}).json()) == 1
    assert client.get(prefix + "/findings", params={"search": "%"}).json() == []


def test_list_query_count_does_not_grow_with_rows(workflow, launch_scan, db, query_counter):
    client, prefix, _payload, _scanner = workflow
    org_id = org_id_of(prefix)
    scan_id = launch_scan(workflow)
    for _ in range(3):
        add_finding(db, org_id, scan_id, evidence_times=(None, None))

    query_counter.reset()
    assert len(client.get(prefix + "/findings", params={"limit": 100}).json()) == 3
    few = query_counter.count

    for _ in range(12):
        add_finding(db, org_id, scan_id, evidence_times=(None, None))
    query_counter.reset()
    assert len(client.get(prefix + "/findings", params={"limit": 100}).json()) == 15
    assert query_counter.count == few


def test_detail_evidence_is_newest_first_and_capped(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    scan_id = launch_scan(workflow)
    base = datetime(2026, 1, 1, tzinfo=UTC)
    # Inserted out of order; 55 rows, so the cap of 50 applies.
    times = [base + timedelta(minutes=(index * 37) % 55) for index in range(55)]
    finding_id = add_finding(db, org_id_of(prefix), scan_id, evidence_times=times)

    evidence = client.get(prefix + f"/findings/{finding_id}").json()["evidence"]
    collected = [parse_time(item["collected_at"]) for item in evidence]
    assert len(collected) == 50
    assert collected == sorted(collected, reverse=True)
    assert collected[0] == base + timedelta(minutes=54)
    assert collected[-1] == base + timedelta(minutes=5)


def test_asset_findings_paginate_with_unscored_last(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    org_id = org_id_of(prefix)
    scan_id = launch_scan(workflow)
    asset = Asset(
        organization_id=org_id, asset_type=AssetType.IPV4, ip_address="192.168.10.10",
        discovery_source="test",
    )
    db.add(asset)
    db.commit()
    priorities = [None, 5.0, 9.0, 1.0, None]
    ids = {add_finding(db, org_id, scan_id, priority=p, asset_id=asset.id): p for p in priorities}

    url = prefix + f"/assets/{asset.id}/findings"
    pages = [client.get(url, params={"limit": 2, "offset": offset}).json() for offset in (0, 2, 4)]
    assert [len(page) for page in pages] == [2, 2, 1]
    ordered = [item["priority_score"] for page in pages for item in page]
    assert ordered == [9.0, 5.0, 1.0, None, None]
    assert {item["id"] for page in pages for item in page} == {str(key) for key in ids}
    assert client.get(url, params={"limit": 101}).status_code == 422
    assert client.get(prefix + f"/assets/{uuid.uuid4()}/findings").status_code == 404


def test_same_status_patch_is_not_audited(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    finding_id = add_finding(db, org_id_of(prefix), launch_scan(workflow))
    url = prefix + f"/findings/{finding_id}"

    response = client.patch(url, json={"status": "open"})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "open"
    assert audit_rows(db, finding_id) == []

    accept = {"status": "accepted_risk", "accepted_risk_reason": "Compensating control in place"}
    assert client.patch(url, json=accept).status_code == 200
    assert len(audit_rows(db, finding_id)) == 1
    # Same status and same reason: nothing changes.
    assert client.patch(url, json=accept).status_code == 200
    assert len(audit_rows(db, finding_id)) == 1
    # A new justification is a change.
    updated = client.patch(url, json={**accept, "accepted_risk_reason": "Isolated network segment"})
    assert updated.json()["accepted_risk_reason"] == "Isolated network segment"
    assert len(audit_rows(db, finding_id)) == 2

    blank_reason = {"status": "accepted_risk", "accepted_risk_reason": "   "}
    assert client.patch(url, json=blank_reason).status_code == 422


def test_leaving_accepted_risk_clears_reason_and_date(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    finding_id = add_finding(db, org_id_of(prefix), launch_scan(workflow))
    url = prefix + f"/findings/{finding_id}"

    accept = {"status": "accepted_risk", "accepted_risk_reason": "Vendor fix pending"}
    accepted = client.patch(url, json=accept).json()
    assert accepted["accepted_risk_at"] and accepted["accepted_risk_reason"] == "Vendor fix pending"
    assert "evidence" in accepted and "remediation_notes" in accepted

    reopened = client.patch(url, json={"status": "open", "accepted_risk_reason": "ignored"}).json()
    assert reopened["status"] == "open"
    assert reopened["accepted_risk_at"] is None
    assert reopened["accepted_risk_reason"] is None

    accept_entry, reopen_entry = audit_rows(db, finding_id)
    assert accept_entry.action == AuditAction.FINDING_ACCEPT_RISK
    assert accept_entry.metadata_["accepted_risk_reason"] == "Vendor fix pending"
    assert reopen_entry.action == AuditAction.FINDING_UPDATE_STATUS
    assert reopen_entry.metadata_["old_status"] == "accepted_risk"
    assert reopen_entry.metadata_["new_status"] == "open"
    assert "accepted_risk_reason" not in reopen_entry.metadata_


def test_leaving_fixed_clears_fixed_at_and_audits_previous_value(workflow, launch_scan, db):
    client, prefix, _payload, _scanner = workflow
    finding_id = add_finding(db, org_id_of(prefix), launch_scan(workflow))
    url = prefix + f"/findings/{finding_id}"

    fixed = client.patch(url, json={"status": "fixed", "accepted_risk_reason": "not stored"}).json()
    assert fixed["fixed_at"] is not None
    assert fixed["accepted_risk_reason"] is None

    reopened = client.patch(url, json={"status": "open"}).json()
    assert reopened["fixed_at"] is None

    _fix_entry, reopen_entry = audit_rows(db, finding_id)
    assert reopen_entry.metadata_["old_status"] == "fixed"
    assert parse_time(reopen_entry.metadata_["previous_fixed_at"]) == parse_time(fixed["fixed_at"])


def test_asset_patch_is_audited_and_keeps_last_seen(workflow, db):
    client, prefix, _payload, _scanner = workflow
    seen = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    asset = Asset(
        organization_id=org_id_of(prefix), asset_type=AssetType.IPV4, ip_address="192.168.10.10",
        discovery_source="test", last_seen=seen,
    )
    db.add(asset)
    db.commit()
    url = prefix + f"/assets/{asset.id}"
    note = "Owned by the infrastructure team"

    response = client.patch(url, json={"notes": note, "is_active": False})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["notes"] == note and body["is_active"] is False
    assert parse_time(body["last_seen"]) == seen

    (entry,) = audit_rows(db, asset.id)
    assert entry.action == AuditAction.ASSET_UPDATE == "asset.update"
    assert entry.metadata_["changed"] == ["notes", "is_active"]
    assert entry.metadata_["is_active"] is False
    assert entry.metadata_["notes_changed"] is True
    assert note not in str(entry.metadata_)

    # Repeating the same values changes nothing and is not audited.
    assert client.patch(url, json={"notes": note, "is_active": False}).status_code == 200
    assert len(audit_rows(db, asset.id)) == 1

    reactivated = client.patch(url, json={"is_active": True}).json()
    assert reactivated["notes"] == note
    entry = audit_rows(db, asset.id)[-1]
    assert entry.metadata_["changed"] == ["is_active"]
    assert entry.metadata_["notes_changed"] is False
    db.expire_all()
    assert db.get(Asset, asset.id).last_seen == seen
