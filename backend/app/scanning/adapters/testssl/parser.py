"""
testssl.sh JSON output parser.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from app.models.finding import FindingConfidence, FindingSeverity
from app.scanning.adapters.base import (
    RawFinding,
    RawFindingEvidence,
    RawScannerResult,
)

logger = logging.getLogger(__name__)

TESTSSL_SEVERITY_MAP = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "WARN": FindingSeverity.LOW,
}


def parse_testssl_json(
    json_path: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    execution_time: float,
) -> RawScannerResult:
    """Parse testssl.sh JSON array output into RawScannerResult."""
    result = RawScannerResult(
        tool_name="testssl",
        exit_code=exit_code,
        execution_time_seconds=execution_time,
        raw_output_path=json_path,
        raw_text=stdout,
    )

    path = Path(json_path)
    if not path.exists() or path.stat().st_size == 0:
        result.error_message = "testssl.sh produced no JSON output"
        return result

    try:
        with open(json_path, encoding="utf-8", errors="replace") as f:
            items = json.load(f)
    except Exception as e:
        logger.error("Failed to parse testssl.sh JSON: %s", e)
        result.error_message = f"Invalid testssl.sh JSON: {e}"
        return result

    if isinstance(items, dict):
        items = [items]

    for item in items:
        if not isinstance(item, dict):
            continue

        raw_sev = str(item.get("severity", "")).upper()
        if raw_sev not in TESTSSL_SEVERITY_MAP:
            # Skip OK, INFO, DEBUG items
            continue

        severity = TESTSSL_SEVERITY_MAP[raw_sev]
        check_id = item.get("id") or "ssl_vulnerability"
        finding_text = item.get("finding") or check_id
        # Flat JSON reports "ip" as "hostname/address"; keep the address.
        target = str(item.get("ip") or item.get("host") or "").rsplit("/", 1)[-1]
        port_raw = item.get("port")
        port = int(port_raw) if port_raw and str(port_raw).isdigit() else 443

        cve_raw = item.get("cve")
        cves = [c for c in str(cve_raw or "").split() if c.upper().startswith("CVE-")]

        cwe_raw = item.get("cwe")
        cwes = str(cwe_raw or "").split()

        finding = RawFinding(
            # The finding text varies between runs (e.g. days to expiry), so it stays
            # out of the title, which feeds the deduplication fingerprint.
            title=f"SSL/TLS: {check_id}",
            description=finding_text,
            source_tool="testssl",
            scanner_reference=check_id,
            confidence=FindingConfidence.CONFIRMED,
            cve_ids=cves,
            cwe_ids=cwes,
            severity=severity,
            port=port,
            protocol="tcp",
            target_address=target,
            evidence=[
                RawFindingEvidence(
                    evidence_type="testssl_finding_json",
                    content=json.dumps(item, indent=2),
                )
            ],
        )
        result.findings.append(finding)

    return result
