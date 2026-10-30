"""
Finding fingerprint generation engine.

Produces deterministic SHA-256 digests from stable finding attributes,
guaranteeing deduplication across scans, time, and scanners.
"""

from __future__ import annotations

import hashlib
import re
import uuid


def slugify(text: str, max_length: int = 80) -> str:
    """Normalize text into lowercase alphanumeric and hyphen slug."""
    clean = re.sub(r"[^\w\s-]", "", text.lower())
    clean = re.sub(r"[-\s]+", "-", clean).strip("-")
    return clean[:max_length]


def compute_finding_fingerprint(
    organization_id: uuid.UUID,
    asset_canonical_id: str,
    port: int | None,
    protocol: str | None,
    cve_ids: list[str],
    scanner_reference: str | None,
    title: str,
) -> str:
    """
    Generate stable 64-character SHA-256 fingerprint hex digest.
    """
    # 1. Determine primary vulnerability identifier
    # Preference: sorted primary CVE ID > scanner reference / template ID > title slug
    primary_cve = sorted(cve_ids)[0].upper() if cve_ids else ""
    if primary_cve:
        vuln_id = primary_cve
    elif scanner_reference:
        vuln_id = slugify(scanner_reference, 60)
    else:
        vuln_id = slugify(title, 60)

    # 2. Port and protocol
    port_str = str(port) if port is not None else "none"
    proto_str = protocol.lower() if protocol else "none"

    # 3. Normalized title slug
    title_slug = slugify(title, 80)

    # 4. Construct pipe-delimited fingerprint input
    parts = [
        str(organization_id),
        asset_canonical_id.strip().lower(),
        port_str,
        proto_str,
        vuln_id,
        title_slug,
    ]
    raw_key = "|".join(parts)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
