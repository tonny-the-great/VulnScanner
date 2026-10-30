"""
Deduplicator — persistent finding reconciliation via stable fingerprint.

The deduplicator works in a fixed number of statements per call (per 500
fingerprints), independent of how many findings a scan produced: existing
findings, scan sightings and the newest evidence are preloaded in bulk, new
rows get client-side ids, and two flushes at the end let SQLAlchemy batch the
INSERTs: findings, evidence and audit rows first, then scan_findings rows
(which have no relationship() to Finding, so the unit of work cannot order
them itself). It never commits; the caller owns the transaction.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from app.core.audit import AuditAction, audit_log
from app.models.finding import (
    Finding,
    FindingConfidence,
    FindingEvidence,
    FindingStatus,
    ScanFinding,
    ScanFindingSnapshot,
)
from app.risk.scorer import calculate_priority_score

logger = logging.getLogger(__name__)

# Upper bound on bound parameters per IN (...) clause.
LOOKUP_CHUNK_SIZE = 500

# Confidence only ever moves up this ladder on re-detection.
_CONFIDENCE_RANK: dict[FindingConfidence, int] = {
    FindingConfidence.UNVERIFIED: 0,
    FindingConfidence.LIKELY: 1,
    FindingConfidence.CONFIRMED: 2,
}


def _chunks(values: list[Any], size: int = LOOKUP_CHUNK_SIZE) -> Iterable[list[Any]]:
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _content_digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", errors="surrogatepass")).hexdigest()


class FindingDeduplicator:
    """Reconciles normalized findings into unique persistent records."""

    def __init__(self, db: Session, organization_id: uuid.UUID) -> None:
        self.db = db
        self.organization_id = organization_id

    def upsert_findings(
        self,
        normalized_items: list[dict],
        scan_id: uuid.UUID,
    ) -> list[Finding]:
        """
        Deduplicate and upsert findings by fingerprint.

        Items are payloads from normalize_raw_finding(). Each one is matched by
        its fingerprint, then by its ``legacy_fingerprint`` (a match there is
        re-keyed to the current fingerprint). Re-detected findings are updated
        (last seen, CVEs/CWEs, highest CVSS, latest severity, confidence never
        downgraded, missing asset/service links, priority score) and FIXED
        ones are reopened with an audit entry. Each distinct finding gets one
        ScanFinding row for this scan, and evidence identical to the newest
        stored evidence of the same type is not stored again.

        Returns a list aligned 1:1 with ``normalized_items``; items that
        describe the same finding map to the same Finding object.

        Ends with a flush and never commits.
        """
        now = datetime.now(UTC)
        fingerprints = sorted({
            fp
            for item in normalized_items
            for fp in (item["fingerprint"], item.get("legacy_fingerprint"))
            if fp
        })
        by_fingerprint = self._load_existing(fingerprints)
        preexisting_ids = sorted({finding.id for finding in by_fingerprint.values()})
        prior_scan_counts = self._load_prior_scan_counts(preexisting_ids, scan_id)
        already_in_scan = self._load_scan_members(scan_id) if preexisting_ids else set()
        newest_evidence = self._load_newest_evidence(preexisting_ids)

        persisted: list[Finding] = []
        touched: dict[uuid.UUID, Finding] = {}
        evidence_seen: set[tuple[uuid.UUID, str, str]] = set()
        observed_evidence: dict[uuid.UUID, dict[tuple[str, str], dict[str, str]]] = {}

        for item in normalized_items:
            finding = self._resolve(item, by_fingerprint)

            if finding is None:
                finding = self._create(item, scan_id, now)
                by_fingerprint[finding.fingerprint] = finding
            else:
                self._redetect(item, finding, scan_id, now, prior_scan_counts)

            touched.setdefault(finding.id, finding)
            self._add_evidence(item, finding, scan_id, now, newest_evidence, evidence_seen)
            for ev in item.get("evidence_raw") or []:
                observed_evidence.setdefault(finding.id, {})[
                    (ev.evidence_type, _content_digest(ev.content))
                ] = {"evidence_type": ev.evidence_type, "content": ev.content}
            persisted.append(finding)

        # One batched flush for findings and evidence. ScanFinding has no
        # relationship() to Finding, so the unit of work would not order its
        # INSERTs after the findings it references; flushing them second keeps
        # the foreign keys valid without adding statements.
        self.db.flush()
        self.db.add_all([
            ScanFinding(scan_id=scan_id, finding_id=finding_id, seen_at=now)
            for finding_id in touched
            if finding_id not in already_in_scan
        ])
        # Capture once per sighting. Retrying the same persistence operation must
        # not replace historical state with subsequent workflow or scan changes.
        self.db.add_all([
            ScanFindingSnapshot(
                scan_id=scan_id,
                finding_id=finding_id,
                captured_at=now,
                severity=finding.severity,
                priority_score=finding.priority_score,
                asset_id=finding.asset_id,
                data={
                    "title": finding.title,
                    "description": finding.description,
                    "source_tool": finding.source_tool,
                    "scanner_reference": finding.scanner_reference,
                    "fingerprint": finding.fingerprint,
                    "confidence": finding.confidence.value,
                    "status": finding.status.value,
                    "cve_ids": list(finding.cve_ids or []),
                    "cwe_ids": list(finding.cwe_ids or []),
                    "cvss_score": (
                        float(finding.cvss_score) if finding.cvss_score is not None else None
                    ),
                    "cvss_vector": finding.cvss_vector,
                    "evidence": list(observed_evidence.get(finding_id, {}).values()),
                },
            )
            for finding_id, finding in touched.items()
            if finding_id not in already_in_scan
        ])
        self.db.flush()
        return persisted

    # ── Bulk loads ────────────────────────────────────────────────────────────

    def _load_existing(self, fingerprints: list[str]) -> dict[str, Finding]:
        """Existing findings of this organization keyed by fingerprint."""
        found: dict[str, Finding] = {}
        for chunk in _chunks(fingerprints):
            stmt = (
                select(Finding)
                .where(
                    Finding.organization_id == self.organization_id,
                    Finding.fingerprint.in_(chunk),
                )
                # Deterministic choice if historic duplicates share a fingerprint.
                .order_by(Finding.first_seen, Finding.id)
            )
            for finding in self.db.scalars(stmt):
                found.setdefault(finding.fingerprint, finding)
        return found

    def _load_prior_scan_counts(
        self, finding_ids: list[uuid.UUID], scan_id: uuid.UUID
    ) -> dict[uuid.UUID, int]:
        """Distinct scans other than this one that recorded each finding."""
        counts: dict[uuid.UUID, int] = {}
        for chunk in _chunks(finding_ids):
            stmt = (
                select(ScanFinding.finding_id, func.count(distinct(ScanFinding.scan_id)))
                .where(ScanFinding.finding_id.in_(chunk), ScanFinding.scan_id != scan_id)
                .group_by(ScanFinding.finding_id)
            )
            for finding_id, count in self.db.execute(stmt):
                counts[finding_id] = int(count)
        return counts

    def _load_scan_members(self, scan_id: uuid.UUID) -> set[uuid.UUID]:
        """Findings already recorded for this scan (e.g. a repeated persist)."""
        stmt = select(ScanFinding.finding_id).where(ScanFinding.scan_id == scan_id)
        return set(self.db.scalars(stmt))

    def _load_newest_evidence(
        self, finding_ids: list[uuid.UUID]
    ) -> dict[tuple[uuid.UUID, str], set[str]]:
        """
        Content digests of the newest evidence per (finding, evidence type).

        rank() keeps every row of the newest observation: one scan may store
        several items of the same type with the same collected_at.
        """
        newest: dict[tuple[uuid.UUID, str], set[str]] = {}
        for chunk in _chunks(finding_ids):
            ranked = (
                select(
                    FindingEvidence.finding_id,
                    FindingEvidence.evidence_type,
                    FindingEvidence.content,
                    func.rank()
                    .over(
                        partition_by=(FindingEvidence.finding_id, FindingEvidence.evidence_type),
                        order_by=FindingEvidence.collected_at.desc(),
                    )
                    .label("position"),
                )
                .where(FindingEvidence.finding_id.in_(chunk))
                .subquery()
            )
            stmt = select(ranked.c.finding_id, ranked.c.evidence_type, ranked.c.content).where(
                ranked.c.position == 1
            )
            for finding_id, evidence_type, content in self.db.execute(stmt):
                newest.setdefault((finding_id, evidence_type), set()).add(_content_digest(content))
        return newest

    # ── Per-item reconciliation (no SQL) ──────────────────────────────────────

    @staticmethod
    def _resolve(item: dict, by_fingerprint: dict[str, Finding]) -> Finding | None:
        fingerprint = item["fingerprint"]
        finding = by_fingerprint.get(fingerprint)
        if finding is not None:
            return finding
        legacy = item.get("legacy_fingerprint")
        if not legacy:
            return None
        finding = by_fingerprint.get(legacy)
        if finding is None or finding.fingerprint != legacy:
            return None
        # Recorded before its target was linked to an asset: re-key it.
        logger.info("Re-keying finding %s to its asset-linked fingerprint", finding.id)
        finding.fingerprint = fingerprint
        del by_fingerprint[legacy]
        by_fingerprint[fingerprint] = finding
        return finding

    def _create(self, item: dict, scan_id: uuid.UUID, now: datetime) -> Finding:
        finding = Finding(
            id=uuid.uuid4(),
            organization_id=self.organization_id,
            asset_id=item["asset_id"],
            service_id=item["service_id"],
            title=item["title"],
            description=item["description"],
            source_tool=item["source_tool"],
            scanner_reference=item["scanner_reference"],
            confidence=item["confidence"],
            cve_ids=list(item["cve_ids"]),
            cwe_ids=list(item["cwe_ids"]),
            severity=item["severity"],
            cvss_score=item["cvss_score"],
            cvss_vector=item["cvss_vector"],
            priority_score=item["priority_score"],
            fingerprint=item["fingerprint"],
            status=FindingStatus.OPEN,
            first_seen=now,
            last_seen=now,
            first_seen_scan_id=scan_id,
            last_seen_scan_id=scan_id,
        )
        self.db.add(finding)
        return finding

    def _redetect(
        self,
        item: dict,
        finding: Finding,
        scan_id: uuid.UUID,
        now: datetime,
        prior_scan_counts: dict[uuid.UUID, int],
    ) -> None:
        """Apply a new observation of an existing (or earlier-in-batch) finding."""
        finding.last_seen = now
        finding.last_seen_scan_id = scan_id

        # If vulnerability was previously marked FIXED and seen again, reopen it
        if finding.status == FindingStatus.FIXED:
            previous_fixed_at = finding.fixed_at
            finding.status = FindingStatus.OPEN
            finding.fixed_at = None
            audit_log(
                self.db,
                commit=False,
                action=AuditAction.FINDING_REOPENED,
                resource_type="finding",
                resource_id=finding.id,
                organization_id=self.organization_id,
                actor_id=None,
                metadata={
                    "scan_id": str(scan_id),
                    "previous_fixed_at": previous_fixed_at.isoformat()
                    if previous_fixed_at
                    else None,
                },
            )

        # Merge CVEs/CWEs without losing any
        merged_cves = sorted(set(finding.cve_ids or []) | set(item["cve_ids"]))
        if merged_cves != list(finding.cve_ids or []):
            finding.cve_ids = merged_cves
        merged_cwes = sorted(set(finding.cwe_ids or []) | set(item["cwe_ids"]))
        if merged_cwes != list(finding.cwe_ids or []):
            finding.cwe_ids = merged_cwes

        # Keep highest CVSS score if newly found
        if item["cvss_score"] is not None and (
            finding.cvss_score is None or item["cvss_score"] > float(finding.cvss_score)
        ):
            finding.cvss_score = item["cvss_score"]
            finding.cvss_vector = item["cvss_vector"]

        # Severity reflects the latest observation; confidence never drops.
        finding.severity = item["severity"]
        if _CONFIDENCE_RANK.get(item["confidence"], -1) > _CONFIDENCE_RANK.get(
            finding.confidence, -1
        ):
            finding.confidence = item["confidence"]

        if finding.asset_id is None and item.get("asset_id") is not None:
            finding.asset_id = item["asset_id"]
        if finding.service_id is None and item.get("service_id") is not None:
            finding.service_id = item["service_id"]

        finding.priority_score = calculate_priority_score(
            severity=finding.severity,
            confidence=finding.confidence,
            cvss_score=float(finding.cvss_score) if finding.cvss_score is not None else None,
            target_ip=item.get("target_ip"),
            scan_recurrence_count=prior_scan_counts.get(finding.id, 0) + 1,
            first_seen=finding.first_seen,
        )

    def _add_evidence(
        self,
        item: dict,
        finding: Finding,
        scan_id: uuid.UUID,
        now: datetime,
        newest_evidence: dict[tuple[uuid.UUID, str], set[str]],
        evidence_seen: set[tuple[uuid.UUID, str, str]],
    ) -> None:
        """Append evidence unless it repeats the newest stored or batch evidence."""
        for ev in item.get("evidence_raw") or []:
            digest = _content_digest(ev.content)
            if digest in newest_evidence.get((finding.id, ev.evidence_type), ()):
                continue
            key = (finding.id, ev.evidence_type, digest)
            if key in evidence_seen:
                continue
            evidence_seen.add(key)
            self.db.add(FindingEvidence(
                id=uuid.uuid4(),
                finding_id=finding.id,
                scan_id=scan_id,
                evidence_type=ev.evidence_type,
                content=ev.content,
                collected_at=now,
            ))
