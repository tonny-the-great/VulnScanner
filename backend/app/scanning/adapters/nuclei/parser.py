"""
Nuclei JSONL output parser.

Parses line-delimited JSON output from Nuclei into standardized RawFinding items.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from urllib.parse import urlparse

from app.models.finding import FindingConfidence, FindingSeverity
from app.scanning.adapters.base import (
    RawFinding,
    RawFindingEvidence,
    RawScannerResult,
)

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}


def parse_nuclei_jsonl(
    jsonl_path: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    execution_time: float,
) -> RawScannerResult:
    """Parse Nuclei JSONL output file into RawScannerResult."""
    result = RawScannerResult(
        tool_name="nuclei",
        exit_code=exit_code,
        execution_time_seconds=execution_time,
        raw_output_path=jsonl_path,
        raw_text=stdout,
    )

    path = Path(jsonl_path)
    if not path.exists():
        result.error_message = "Nuclei output file is missing"
        return result
    if path.stat().st_size == 0:
        if exit_code != 0:
            result.error_message = stderr or stdout or "Nuclei execution failed with no output"
        return result

    with open(jsonl_path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                item = json.loads(line_str)
            except json.JSONDecodeError:
                result.error_message = "Nuclei output contains invalid JSON"
                continue

            if not isinstance(item, dict):
                result.error_message = "Nuclei output contains an unexpected JSON value"
                continue

            template_id = item.get("template-id") or item.get("templateID") or "unknown"
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            title = info.get("name") or template_id
            description = info.get("description")
            raw_severity = (info.get("severity") or "info").lower()
            severity = SEVERITY_MAP.get(raw_severity, FindingSeverity.INFO)

            classification = info.get("classification") or {}
            cve_ids_raw = classification.get("cve-id") or []
            if isinstance(cve_ids_raw, str):
                cve_ids = [cve_ids_raw]
            else:
                cve_ids = [str(c) for c in cve_ids_raw]

            cwe_ids_raw = classification.get("cwe-id") or []
            if isinstance(cwe_ids_raw, str):
                cwe_ids = [cwe_ids_raw]
            else:
                cwe_ids = [str(c) for c in cwe_ids_raw]

            cvss_score_raw = classification.get("cvss-score")
            try:
                cvss_score = float(cvss_score_raw) if cvss_score_raw not in (None, "") else None
            except (TypeError, ValueError):
                cvss_score = None
            cvss_vector = classification.get("cvss-metrics")

            host_str = item.get("host", "")
            matched_at = item.get("matched-at", host_str)

            # Determine port from host_str or matched_at
            port: int | None = None
            try:
                parsed = urlparse(matched_at if "://" in matched_at else f"http://{matched_at}")
                if parsed.port:
                    port = parsed.port
                elif parsed.scheme == "https":
                    port = 443
                elif parsed.scheme == "http":
                    port = 80
            except ValueError:
                logger.debug("Could not determine port from %r", matched_at)

            evidence_items: list[RawFindingEvidence] = []
            if item.get("request"):
                evidence_items.append(
                    RawFindingEvidence(
                        evidence_type="http_request",
                        content=str(item["request"])[:5000],
                    )
                )
            if item.get("response"):
                evidence_items.append(
                    RawFindingEvidence(
                        evidence_type="http_response",
                        content=str(item["response"])[:5000],
                    )
                )
            if item.get("curl-command"):
                evidence_items.append(
                    RawFindingEvidence(
                        evidence_type="curl_command",
                        content=str(item["curl-command"])[:1000],
                    )
                )
            if item.get("extracted-results"):
                evidence_items.append(
                    RawFindingEvidence(
                        evidence_type="extracted_results",
                        content=json.dumps(item["extracted-results"])[:1000],
                    )
                )

            # Nuclei matchers produce active proof -> CONFIRMED
            confidence = FindingConfidence.CONFIRMED

            finding = RawFinding(
                title=f"Nuclei: {title}",
                description=description,
                source_tool="nuclei",
                scanner_reference=template_id,
                confidence=confidence,
                cve_ids=cve_ids,
                cwe_ids=cwe_ids,
                severity=severity,
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                port=port,
                protocol="tcp",
                target_address=host_str or matched_at,
                evidence=evidence_items,
            )
            result.findings.append(finding)

    return result
