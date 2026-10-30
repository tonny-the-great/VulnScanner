"""Unit tests for finding fingerprint generation."""

import uuid

from app.scanning.normalization.fingerprint import compute_finding_fingerprint, slugify


def test_slugify():
    assert (
        slugify("Apache HTTP Server 2.4.49 - Path Traversal")
        == "apache-http-server-2449-path-traversal"
    )
    assert (
        slugify("SSL/TLS: Weak Cipher Suite (DES-CBC3-SHA)")
        == "ssltls-weak-cipher-suite-des-cbc3-sha"
    )


def test_fingerprint_deterministic():
    org_id = uuid.uuid4()
    fp1 = compute_finding_fingerprint(
        organization_id=org_id,
        asset_canonical_id="192.168.1.100",
        port=80,
        protocol="tcp",
        cve_ids=["CVE-2021-41773"],
        scanner_reference="http-vuln-cve2021-41773",
        title="Path Traversal",
    )
    fp2 = compute_finding_fingerprint(
        organization_id=org_id,
        asset_canonical_id="192.168.1.100",
        port=80,
        protocol="tcp",
        cve_ids=["CVE-2021-41773"],
        scanner_reference="nuclei-template-cve-2021-41773",
        title="Path Traversal",
    )
    # Since CVE matches and port/proto/asset matches, fingerprints match!
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex string


def test_fingerprint_differs_on_port():
    org_id = uuid.uuid4()
    fp1 = compute_finding_fingerprint(
        organization_id=org_id,
        asset_canonical_id="192.168.1.100",
        port=80,
        protocol="tcp",
        cve_ids=["CVE-2021-41773"],
        scanner_reference=None,
        title="Path Traversal",
    )
    fp2 = compute_finding_fingerprint(
        organization_id=org_id,
        asset_canonical_id="192.168.1.100",
        port=8080,
        protocol="tcp",
        cve_ids=["CVE-2021-41773"],
        scanner_reference=None,
        title="Path Traversal",
    )
    assert fp1 != fp2
