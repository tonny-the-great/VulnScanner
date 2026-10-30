"""
Finding normalization layer.

Maps RawFinding objects into normalized attribute dictionaries ready for deduplication and
persistence.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.models.asset import Asset, Service
from app.risk.scorer import calculate_priority_score
from app.scanning.adapters.base import RawFinding
from app.scanning.normalization.fingerprint import compute_finding_fingerprint


def normalize_raw_finding(
    raw: RawFinding,
    organization_id: uuid.UUID,
    asset: Asset | None,
    service: Service | None,
) -> dict[str, Any]:
    """
    Produce normalized finding payload with computed fingerprint and priority score.

    Besides the Finding attributes, the payload carries:
      - ``target_ip``: the linked asset's IP address (or None), for re-scoring.
      - ``legacy_fingerprint``: the fingerprint this finding had when it was
        not linked to an asset (keyed on ``raw.target_address``), or None when
        that would equal ``fingerprint``. The deduplicator uses it to merge
        findings recorded before asset linking resolved their target.
    """
    # Canonical asset address for fingerprinting
    asset_canonical_id = "unknown"
    if asset:
        asset_canonical_id = asset.ip_address or asset.hostname or asset.domain or str(asset.id)
    elif raw.target_address:
        asset_canonical_id = raw.target_address

    def fingerprint_for(canonical_id: str) -> str:
        return compute_finding_fingerprint(
            organization_id=organization_id,
            asset_canonical_id=canonical_id,
            port=raw.port,
            protocol=raw.protocol,
            cve_ids=raw.cve_ids,
            scanner_reference=raw.scanner_reference,
            title=raw.title,
        )

    # Stable fingerprint
    fingerprint = fingerprint_for(asset_canonical_id)

    legacy_fingerprint: str | None = None
    target_address = (raw.target_address or "").strip()
    # The fingerprint lowercases and strips the canonical id, so compare likewise.
    if asset and target_address and target_address.lower() != asset_canonical_id.strip().lower():
        legacy_fingerprint = fingerprint_for(raw.target_address)

    # Documented priority score
    target_ip = asset.ip_address if asset else None
    priority_score = calculate_priority_score(
        severity=raw.severity,
        confidence=raw.confidence,
        cvss_score=raw.cvss_score,
        target_ip=target_ip,
    )

    return {
        "organization_id": organization_id,
        "asset_id": asset.id if asset else None,
        "service_id": service.id if service else None,
        "title": raw.title.strip(),
        "description": raw.description.strip() if raw.description else None,
        "source_tool": raw.source_tool,
        "scanner_reference": raw.scanner_reference,
        "confidence": raw.confidence,
        "cve_ids": sorted(list(set(raw.cve_ids))),
        "cwe_ids": sorted(list(set(raw.cwe_ids))),
        "severity": raw.severity,
        "cvss_score": raw.cvss_score,
        "cvss_vector": raw.cvss_vector,
        "priority_score": priority_score,
        "fingerprint": fingerprint,
        "legacy_fingerprint": legacy_fingerprint,
        "target_ip": target_ip,
        "evidence_raw": raw.evidence,
    }
