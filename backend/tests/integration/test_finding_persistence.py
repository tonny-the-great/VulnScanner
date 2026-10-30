"""Scan result persistence: bulk statements, merging, history and atomicity."""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.models.asset import Asset, AssetType, Service, ServiceProtocol
from app.models.audit import AuditLog
from app.models.authorization import ScopeAuthorization
from app.models.finding import (
    Finding,
    FindingConfidence,
    FindingEvidence,
    FindingSeverity,
    FindingStatus,
    ScanFinding,
)
from app.models.organization import Organization
from app.models.scan import Scan, ScanProfile, ScanStatus
from app.models.user import User
from app.risk.scorer import calculate_priority_score
from app.scanning.adapters.base import (
    RawDiscoveredAsset,
    RawDiscoveredService,
    RawFinding,
    RawFindingEvidence,
)
from app.scanning.normalization import AssetNormalizer, FindingDeduplicator, normalize_raw_finding

STATEMENT_TOLERANCE = 2


@pytest.fixture
def lab(db):
    tag = uuid.uuid4().hex
    owner = User(
        email=f"persist-{tag}@example.com",
        full_name="Persistence Owner",
        password_hash="unused-fixture",
    )
    organization = Organization(name=f"Persistence Lab {tag}", slug=f"persist-{tag}")
    profile = ScanProfile(name=f"persist-{tag}", display_name="Persistence fixture", config_json={})
    db.add_all([owner, organization, profile])
    db.flush()
    authorization = ScopeAuthorization(
        organization_id=organization.id, title="Authorized persistence fixture",
        signer_name="Persistence Owner", signer_email=owner.email,
        authorization_date=datetime.now(UTC).date(), created_by=owner.id,
    )
    db.add(authorization)
    db.flush()
    # Plain values: committed ORM attributes expire and would reload.
    org_id, owner_id, authorization_id, profile_id = (
        organization.id,
        owner.id,
        authorization.id,
        profile.id,
    )
    db.commit()

    def new_scan() -> uuid.UUID:
        scan = Scan(
            id=uuid.uuid4(), organization_id=org_id, authorization_id=authorization_id,
            profile_id=profile_id, created_by=owner_id, status=ScanStatus.RUNNING,
        )
        db.add(scan)
        db.commit()
        return scan.id

    def persist(raws, scan_id, asset=None, service=None):
        items = [normalize_raw_finding(raw, org_id, asset, service) for raw in raws]
        return FindingDeduplicator(db, org_id).upsert_findings(items, scan_id)

    def findings():
        return list(db.scalars(select(Finding).where(Finding.organization_id == org_id)))

    return SimpleNamespace(org_id=org_id, new_scan=new_scan, persist=persist, findings=findings)


def raw_finding(
    index=0,
    *,
    target="10.20.30.40",
    cvss=None,
    confidence=FindingConfidence.LIKELY,
    severity=FindingSeverity.MEDIUM,
    evidence="banner: example 1.0",
    evidence_type="banner",
):
    return RawFinding(
        title=f"Persistence fixture finding {index}",
        description="Recorded by fixture",
        source_tool="nmap",
        scanner_reference=f"fixture-{index}",
        confidence=confidence,
        cve_ids=[],
        cwe_ids=[],
        severity=severity,
        cvss_score=cvss,
        port=443,
        protocol="tcp",
        target_address=target,
        evidence=[RawFindingEvidence(evidence_type=evidence_type, content=evidence)]
        if evidence
        else [],
    )


def raw_asset(index, *, services=2, hostname=None):
    return RawDiscoveredAsset(
        asset_type=AssetType.IPV4,
        ip_address=f"10.77.{index // 250}.{index % 250 + 1}",
        hostname=hostname,
        services=[
            RawDiscoveredService(protocol=ServiceProtocol.TCP, port=1000 + port, service_name="svc")
            for port in range(services)
        ],
    )


def count(db, model, *conditions):
    return db.scalar(select(func.count()).select_from(model).where(*conditions))


# ── Statement counts ──────────────────────────────────────────────────────────

def test_finding_statement_count_does_not_grow_with_batch_size(db, lab, query_counter):
    new_counts, repeat_counts = [], []
    for size in (20, 100):
        raws = [raw_finding(f"{size}-{i}", evidence=f"evidence {i}") for i in range(size)]
        scan_id = lab.new_scan()
        query_counter.reset()
        lab.persist(raws, scan_id)
        new_counts.append(query_counter.count)
        db.commit()

        # Seen again by a second scan: updates only, identical evidence skipped.
        second_scan = lab.new_scan()
        query_counter.reset()
        lab.persist(raws, second_scan)
        repeat_counts.append(query_counter.count)
        db.commit()

    assert abs(new_counts[0] - new_counts[1]) <= STATEMENT_TOLERANCE, new_counts
    assert abs(repeat_counts[0] - repeat_counts[1]) <= STATEMENT_TOLERANCE, repeat_counts
    # Bulk loads plus batched writes, never one statement per finding.
    assert max(new_counts + repeat_counts) <= 10, (new_counts, repeat_counts)
    assert len(lab.findings()) == 120


def test_asset_statement_count_does_not_grow_with_batch_size(db, lab, query_counter):
    new_counts, repeat_counts = [], []
    for offset, size in ((0, 5), (100, 40)):
        raws = [raw_asset(offset + i) for i in range(size)]
        query_counter.reset()
        AssetNormalizer(db, lab.org_id).upsert_discovered_assets(raws, "scan_orchestrator")
        new_counts.append(query_counter.count)
        db.commit()

        query_counter.reset()
        AssetNormalizer(db, lab.org_id).upsert_discovered_assets(raws, "scan_orchestrator")
        repeat_counts.append(query_counter.count)
        db.commit()

    assert abs(new_counts[0] - new_counts[1]) <= STATEMENT_TOLERANCE, new_counts
    assert abs(repeat_counts[0] - repeat_counts[1]) <= STATEMENT_TOLERANCE, repeat_counts
    assert max(new_counts + repeat_counts) <= 8, (new_counts, repeat_counts)
    assert count(db, Asset, Asset.organization_id == lab.org_id) == 45


# ── Transactions ──────────────────────────────────────────────────────────────

def test_normalization_layer_never_commits(db, lab):
    scan_id = lab.new_scan()
    assets = AssetNormalizer(db, lab.org_id).upsert_discovered_assets(
        [raw_asset(1)], "scan_orchestrator"
    )
    lab.persist(
        [raw_finding(1, target="10.77.0.2")],
        scan_id,
        asset=assets[0],
        service=assets[0].services[0],
    )
    db.rollback()

    assert count(db, Asset, Asset.organization_id == lab.org_id) == 0
    assert lab.findings() == []
    assert count(db, ScanFinding, ScanFinding.scan_id == scan_id) == 0
    assert count(db, FindingEvidence, FindingEvidence.scan_id == scan_id) == 0


# ── Re-detection ──────────────────────────────────────────────────────────────

def test_redetection_raises_priority_upgrades_confidence_and_links_asset(db, lab):
    first = lab.persist([raw_finding(target="192.168.50.5", cvss=5.0)], lab.new_scan())[0]
    db.commit()
    finding_id, first_priority = first.id, float(first.priority_score)
    assert first.asset_id is None

    asset = AssetNormalizer(db, lab.org_id).upsert_discovered_assets([RawDiscoveredAsset(
        asset_type=AssetType.IPV4, ip_address="192.168.50.5",
        services=[RawDiscoveredService(protocol=ServiceProtocol.TCP, port=443)],
    )], "scan_orchestrator")[0]
    second = lab.persist(
        [raw_finding(target="192.168.50.5", cvss=9.0, confidence=FindingConfidence.CONFIRMED,
                     severity=FindingSeverity.CRITICAL)],
        lab.new_scan(), asset=asset, service=asset.services[0],
    )[0]
    db.commit()
    assert second.id == finding_id
    assert float(second.priority_score) > first_priority
    assert second.confidence == FindingConfidence.CONFIRMED
    assert second.severity == FindingSeverity.CRITICAL
    assert float(second.cvss_score) == 9.0
    assert second.asset_id == asset.id
    assert second.service_id == asset.services[0].id

    third = lab.persist(
        [raw_finding(target="192.168.50.5", cvss=4.0, confidence=FindingConfidence.LIKELY,
                     severity=FindingSeverity.HIGH)],
        lab.new_scan(), asset=asset,
    )[0]
    db.commit()
    assert third.confidence == FindingConfidence.CONFIRMED  # never downgraded
    assert third.severity == FindingSeverity.HIGH  # latest observation
    assert float(third.cvss_score) == 9.0  # highest kept
    assert len(lab.findings()) == 1


def test_three_scans_add_the_recurrence_bonus(db, lab):
    raw = raw_finding(cvss=6.0)
    priorities = []
    for _ in range(3):
        finding = lab.persist([raw], lab.new_scan())[0]
        db.commit()
        priorities.append(float(finding.priority_score))

    base = calculate_priority_score(FindingSeverity.MEDIUM, FindingConfidence.LIKELY, 6.0)
    assert priorities[0] == priorities[1] == base
    assert priorities[2] == pytest.approx(base + 0.3)


# ── Per-scan history and evidence ─────────────────────────────────────────────

def test_scan_membership_is_recorded_once_per_finding_and_scan(db, lab):
    scan_id = lab.new_scan()
    raws = [raw_finding(1), raw_finding(1), raw_finding(2)]
    persisted = lab.persist(raws, scan_id)
    assert persisted[0] is persisted[1]
    assert persisted[0] is not persisted[2]
    db.commit()
    assert count(db, ScanFinding, ScanFinding.scan_id == scan_id) == 2

    # The cancel path may persist the same results twice.
    lab.persist(raws, scan_id)
    db.commit()
    assert count(db, ScanFinding, ScanFinding.scan_id == scan_id) == 2
    finding_ids = [f.id for f in lab.findings()]
    assert count(db, FindingEvidence, FindingEvidence.finding_id.in_(finding_ids)) == 2

    next_scan = lab.new_scan()
    lab.persist(raws, next_scan)
    db.commit()
    assert count(db, ScanFinding, ScanFinding.scan_id == next_scan) == 2
    assert count(db, ScanFinding, ScanFinding.finding_id == persisted[0].id) == 2


def test_identical_evidence_is_stored_once_and_changes_add_rows(db, lab):
    finding = lab.persist([raw_finding(evidence="Server: nginx/1.18")], lab.new_scan())[0]
    db.commit()
    finding_id = finding.id

    lab.persist([raw_finding(evidence="Server: nginx/1.18")], lab.new_scan())
    db.commit()
    assert count(db, FindingEvidence, FindingEvidence.finding_id == finding_id) == 1

    lab.persist([raw_finding(evidence="Server: nginx/1.20")], lab.new_scan())
    db.commit()
    assert count(db, FindingEvidence, FindingEvidence.finding_id == finding_id) == 2

    # A different evidence type with the same content is new evidence.
    lab.persist(
        [raw_finding(evidence="Server: nginx/1.20", evidence_type="header")], lab.new_scan()
    )
    db.commit()
    assert count(db, FindingEvidence, FindingEvidence.finding_id == finding_id) == 3


def test_fixed_finding_seen_again_is_reopened_with_audit_entry(db, lab):
    finding = lab.persist([raw_finding()], lab.new_scan())[0]
    fixed_at = datetime.now(UTC) - timedelta(days=3)
    finding.status, finding.fixed_at = FindingStatus.FIXED, fixed_at
    db.commit()
    finding_id = finding.id

    scan_id = lab.new_scan()
    reopened = lab.persist([raw_finding()], scan_id)[0]
    assert reopened.status == FindingStatus.OPEN
    assert reopened.fixed_at is None
    audit_filter = (AuditLog.action == "finding.reopened", AuditLog.object_id == str(finding_id))
    entry = db.scalars(select(AuditLog).where(*audit_filter)).one()
    assert entry.organization_id == lab.org_id
    assert entry.actor_id is None
    assert entry.metadata_["scan_id"] == str(scan_id)
    assert entry.metadata_["previous_fixed_at"].startswith(fixed_at.isoformat()[:19])

    # Same transaction: rolling back drops both the reopening and its audit entry.
    db.rollback()
    assert db.get(Finding, finding_id).status == FindingStatus.FIXED
    assert count(db, AuditLog, *audit_filter) == 0


# ── Fingerprint compatibility ─────────────────────────────────────────────────

def test_finding_recorded_before_linking_is_merged_and_rekeyed(db, lab):
    unlinked = lab.persist([raw_finding(target="https://example.test")], lab.new_scan())[0]
    db.commit()
    finding_id, legacy_fingerprint = unlinked.id, unlinked.fingerprint

    asset = AssetNormalizer(db, lab.org_id).upsert_discovered_assets([RawDiscoveredAsset(
        asset_type=AssetType.HOSTNAME, hostname="example.test",
    )], "scan_orchestrator")[0]
    item = normalize_raw_finding(
        raw_finding(target="https://example.test"), lab.org_id, asset, None
    )
    assert item["legacy_fingerprint"] == legacy_fingerprint
    assert item["fingerprint"] != legacy_fingerprint

    linked = FindingDeduplicator(db, lab.org_id).upsert_findings([item], lab.new_scan())[0]
    db.commit()
    assert linked.id == finding_id
    assert linked.fingerprint == item["fingerprint"]
    assert linked.asset_id == asset.id
    assert len(lab.findings()) == 1

    # The next scan matches on the new fingerprint directly.
    again = lab.persist([raw_finding(target="https://example.test")], lab.new_scan(), asset=asset)[
        0
    ]
    assert again.id == finding_id
    assert len(lab.findings()) == 1


def test_normalized_payload_reports_target_ip_and_legacy_fingerprint(lab):
    raw = raw_finding(target="10.1.1.1")
    unlinked = normalize_raw_finding(raw, lab.org_id, None, None)
    assert unlinked["target_ip"] is None
    assert unlinked["legacy_fingerprint"] is None

    same_target = Asset(id=uuid.uuid4(), ip_address="10.1.1.1", asset_type=AssetType.IPV4)
    linked = normalize_raw_finding(raw, lab.org_id, same_target, None)
    assert linked["target_ip"] == "10.1.1.1"
    assert linked["fingerprint"] == unlinked["fingerprint"]
    assert linked["legacy_fingerprint"] is None


# ── Assets ────────────────────────────────────────────────────────────────────

def test_duplicate_raw_assets_in_one_batch_share_one_asset(db, lab):
    raws = [
        RawDiscoveredAsset(asset_type=AssetType.IPV4, ip_address="10.88.0.1", services=[
            RawDiscoveredService(protocol=ServiceProtocol.TCP, port=22)]),
        RawDiscoveredAsset(asset_type=AssetType.IPV4, ip_address="10.88.0.1", services=[
            RawDiscoveredService(protocol=ServiceProtocol.TCP, port=22, product="OpenSSH"),
            RawDiscoveredService(protocol=ServiceProtocol.TCP, port=80)]),
        RawDiscoveredAsset(asset_type=AssetType.HOSTNAME, hostname="Batch.Example.Test"),
        RawDiscoveredAsset(asset_type=AssetType.HOSTNAME, hostname="batch.example.test"),
    ]
    assets = AssetNormalizer(db, lab.org_id).upsert_discovered_assets(raws, "scan_orchestrator")
    db.commit()
    assert len(assets) == len(raws)
    assert assets[0] is assets[1]
    assert assets[2] is assets[3]
    assert count(db, Asset, Asset.organization_id == lab.org_id) == 2
    assert sorted(s.port for s in assets[0].services) == [22, 80]
    assert count(db, Service, Service.asset_id == assets[0].id) == 2
    assert next(s for s in assets[0].services if s.port == 22).product == "OpenSSH"


def test_hostnames_match_case_insensitively_without_changing_ip(db, lab):
    first = AssetNormalizer(db, lab.org_id).upsert_discovered_assets([RawDiscoveredAsset(
        asset_type=AssetType.HOSTNAME, hostname="Web.Example.Test", ip_address="10.99.0.1",
    )], "scan_orchestrator")[0]
    db.commit()
    asset_id = first.id

    again = AssetNormalizer(db, lab.org_id).upsert_discovered_assets([RawDiscoveredAsset(
        asset_type=AssetType.HOSTNAME, hostname="web.example.test", ip_address="10.99.0.2",
    )], "scan_orchestrator")[0]
    db.commit()
    assert again.id == asset_id
    assert again.ip_address == "10.99.0.1"
    assert count(db, Asset, Asset.organization_id == lab.org_id) == 1


def test_new_asset_services_are_visible_without_extra_select(db, lab, query_counter):
    assets = AssetNormalizer(db, lab.org_id).upsert_discovered_assets(
        [raw_asset(i, services=3) for i in range(4)], "scan_orchestrator",
    )
    query_counter.reset()
    service_ids = [service.id for asset in assets for service in asset.services]
    asset_ids = [asset.id for asset in assets]
    assert query_counter.count == 0, query_counter.statements
    assert len(service_ids) == 12 and all(service_ids)
    assert len(set(asset_ids)) == 4
    db.commit()
