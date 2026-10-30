"""
Nmap XML output parser.

Parses Nmap XML output into standardized RawDiscoveredAsset and RawFinding items.
The standard-library parser does not resolve external entities, so the file
cannot pull in local files or network resources (XXE).
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import iterparse

from app.models.asset import AssetType, ServiceProtocol, ServiceState
from app.models.finding import FindingConfidence, FindingSeverity
from app.scanning.adapters.base import (
    RawDiscoveredAsset,
    RawDiscoveredService,
    RawFinding,
    RawFindingEvidence,
    RawScannerResult,
)

logger = logging.getLogger(__name__)

CVE_REGEX = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
# "NOT VULNERABLE" and "LIKELY VULNERABLE" (NSE vulns library states) are not confirmations.
VULNERABLE_STATE_REGEX = re.compile(r"(?<!NOT )(?<!LIKELY )\bVULNERABLE\b", re.IGNORECASE)
# State line written by the NSE vulns library for each checked vulnerability.
STATE_LINE_REGEX = re.compile(
    r"State:\s*(NOT VULNERABLE|LIKELY VULNERABLE|VULNERABLE)", re.IGNORECASE
)
RISK_FACTOR_REGEX = re.compile(r"Risk factor:\s*(Critical|High|Medium|Low)\b", re.IGNORECASE)
LEAST_STRENGTH_REGEX = re.compile(r"least strength:\s*([A-F])\b", re.IGNORECASE)
CVSS_TOKEN_REGEX = re.compile(r"\d{1,2}(?:\.\d+)?")
LEGACY_SCRIPT_MARKERS = ("vuln", "cve")

_SEVERITY_RANK = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}


def _iter_elements(xml_path: str):
    """
    Yield complete <host> and runstats <hosts> elements, tolerating a file
    truncated by timeout or cancellation.
    """
    for _, elem in iterparse(xml_path, events=("end",)):
        if elem.tag in ("host", "hosts"):
            yield elem


def _severity_from_cvss(score: float) -> FindingSeverity:
    if score >= 9:
        return FindingSeverity.CRITICAL
    if score >= 7:
        return FindingSeverity.HIGH
    if score >= 4:
        return FindingSeverity.MEDIUM
    if score > 0:
        return FindingSeverity.LOW
    return FindingSeverity.INFO


def _classify_vulns_states(
    output: str, states: list[re.Match[str]],
) -> tuple[FindingConfidence, FindingSeverity, list[str]] | None:
    """
    Classify output from the NSE vulns library, considering only reported
    (not NOT VULNERABLE) entries.
    """
    reported: list[str] = []
    confirmed = False
    for index, match in enumerate(states):
        state = match.group(1).upper()
        if state == "NOT VULNERABLE":
            continue
        confirmed = confirmed or state == "VULNERABLE"
        # Each entry's IDs and risk factor follow its State line; text before the
        # first State line (the entry title) belongs to the first entry.
        start = 0 if index == 0 else match.start()
        end = states[index + 1].start() if index + 1 < len(states) else len(output)
        reported.append(output[start:end])
    if not reported:
        return None
    block = "\n".join(reported)
    cves = sorted({c.upper() for c in CVE_REGEX.findall(block)})
    risks = [FindingSeverity(r.lower()) for r in RISK_FACTOR_REGEX.findall(block)]
    if risks:
        severity = max(risks, key=_SEVERITY_RANK.__getitem__)
    else:
        severity = FindingSeverity.HIGH if cves else FindingSeverity.MEDIUM
    confidence = FindingConfidence.CONFIRMED if confirmed else FindingConfidence.LIKELY
    return confidence, severity, cves


def _classify_vulners(output: str) -> tuple[FindingSeverity, list[str], float | None] | None:
    """vulners matches CVEs by product version only, so its results are unverified."""
    cves: set[str] = set()
    best: float | None = None
    for line in output.splitlines():
        line_cves = CVE_REGEX.findall(line)
        if not line_cves:
            continue
        cves.update(c.upper() for c in line_cves)
        for token in line.split():
            if CVSS_TOKEN_REGEX.fullmatch(token):
                score = float(token)
                if score <= 10 and (best is None or score > best):
                    best = score
    if not cves:
        return None
    severity = _severity_from_cvss(best) if best is not None else FindingSeverity.MEDIUM
    return severity, sorted(cves), best


def _classify_script(
    script_id: str, output: str,
) -> tuple[FindingConfidence, FindingSeverity, list[str], float | None] | None:
    """Decide whether a script result is a finding; returns (confidence, severity, CVEs, CVSS)."""
    states = list(STATE_LINE_REGEX.finditer(output))
    if states:
        classified = _classify_vulns_states(output, states)
        if classified is None:
            return None
        confidence, severity, cves = classified
        return confidence, severity, cves, None

    if script_id == "ssl-enum-ciphers":
        grades = [g.upper() for g in LEAST_STRENGTH_REGEX.findall(output)]
        if not grades:
            return None
        worst = max(grades)
        if worst == "C":
            return FindingConfidence.CONFIRMED, FindingSeverity.MEDIUM, [], None
        if worst in ("D", "E", "F"):
            return FindingConfidence.CONFIRMED, FindingSeverity.HIGH, [], None
        return None

    if script_id == "http-security-headers":
        return FindingConfidence.CONFIRMED, FindingSeverity.INFO, [], None

    if script_id == "vulners":
        vulners = _classify_vulners(output)
        if vulners is None:
            return None
        severity, cves, score = vulners
        return FindingConfidence.UNVERIFIED, severity, cves, score

    if any(marker in script_id for marker in LEGACY_SCRIPT_MARKERS):
        cves = sorted({c.upper() for c in CVE_REGEX.findall(output)})
        severity = FindingSeverity.HIGH if cves else FindingSeverity.MEDIUM
        upper = output.upper()
        if VULNERABLE_STATE_REGEX.search(output):
            return FindingConfidence.CONFIRMED, severity, cves, None
        if "LIKELY VULNERABLE" in upper:
            return FindingConfidence.LIKELY, severity, cves, None
        if "NOT VULNERABLE" in upper:
            return None
        return FindingConfidence.LIKELY, severity, cves, None

    return None


def _script_finding(
    script_elem: ET.Element,
    target_ref: str,
    port_num: int | None,
    protocol: str | None,
) -> RawFinding | None:
    script_id = script_elem.get("id", "")
    script_output = script_elem.get("output", "")
    classified = _classify_script(script_id, script_output)
    if classified is None:
        return None
    confidence, severity, cves, cvss_score = classified
    location = f"port {port_num}/{protocol}" if port_num is not None else "host"
    return RawFinding(
        # The title feeds finding fingerprints; keep its format stable.
        title=f"Nmap: {script_id} on {location}",
        description=script_output.strip()[:2000],
        source_tool="nmap",
        scanner_reference=script_id,
        confidence=confidence,
        cve_ids=cves,
        cwe_ids=[],
        severity=severity,
        cvss_score=cvss_score,
        port=port_num,
        protocol=protocol,
        target_address=target_ref,
        evidence=[
            RawFindingEvidence(
                evidence_type="nmap_script_output",
                content=f"Script: {script_id}\n\n{script_output}",
            )
        ],
    )


def _runstats_warnings(hosts_elem: ET.Element) -> list[str]:
    def count(attr: str) -> int:
        value = hosts_elem.get(attr, "")
        return int(value) if value.isdigit() else 0

    up, down, total = count("up"), count("down"), count("total")
    if total > 0 and up == 0:
        return ["No hosts responded to nmap; results are incomplete"]
    if down > 0:
        return [f"{down} of {total or up + down} addresses did not respond"]
    return []


def parse_nmap_xml(
    xml_path: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    execution_time: float,
) -> RawScannerResult:
    """Parse Nmap XML output file safely into RawScannerResult."""
    result = RawScannerResult(
        tool_name="nmap",
        exit_code=exit_code,
        execution_time_seconds=execution_time,
        raw_output_path=xml_path,
        raw_text=stdout,
    )

    path = Path(xml_path)
    if not path.exists() or path.stat().st_size == 0:
        result.error_message = "Nmap produced no XML output"
        return result

    elements = _iter_elements(xml_path)
    while True:
        try:
            host_elem = next(elements)
        except StopIteration:
            break
        except (ET.ParseError, DefusedXmlException) as e:
            # Hosts parsed before the error are kept; nmap writes each host when it finishes.
            logger.error("Failed to parse Nmap XML at %s: %s", xml_path, e)
            result.error_message = f"Invalid XML from Nmap: {e}"
            break
        if host_elem.tag == "hosts":
            # <runstats><hosts up= down= total=/> is written only when nmap finishes.
            result.warnings.extend(_runstats_warnings(host_elem))
            continue
        # Check host status
        status_elem = host_elem.find("status")
        if status_elem is not None and status_elem.get("state") != "up":
            continue

        ip_addr: str | None = None
        hostname: str | None = None
        asset_type = AssetType.IPV4

        for addr_elem in host_elem.findall("address"):
            addr_type = addr_elem.get("addrtype")
            addr = addr_elem.get("addr")
            if addr_type == "ipv4":
                ip_addr = addr
                asset_type = AssetType.IPV4
            elif addr_type == "ipv6":
                ip_addr = addr
                asset_type = AssetType.IPV6

        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            first_host = hostnames_elem.find("hostname")
            if first_host is not None:
                hostname = first_host.get("name")

        # OS detection
        os_name: str | None = None
        os_accuracy: int | None = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name")
                acc = osmatch.get("accuracy")
                if acc and acc.isdigit():
                    os_accuracy = int(acc)

        discovered_services: list[RawDiscoveredService] = []

        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_id_str = port_elem.get("portid")
                protocol_str = port_elem.get("protocol", "tcp").lower()
                if not port_id_str or not port_id_str.isdigit():
                    continue

                port_num = int(port_id_str)
                protocol = ServiceProtocol.UDP if protocol_str == "udp" else ServiceProtocol.TCP

                state_elem = port_elem.find("state")
                state = ServiceState.OPEN
                if state_elem is not None:
                    s_str = state_elem.get("state", "open").lower()
                    if s_str == "filtered":
                        state = ServiceState.FILTERED
                    elif s_str == "closed":
                        state = ServiceState.CLOSED

                service_elem = port_elem.find("service")
                service_name = service_elem.get("name") if service_elem is not None else None
                product = service_elem.get("product") if service_elem is not None else None
                version = service_elem.get("version") if service_elem is not None else None
                extra_info = service_elem.get("extrainfo") if service_elem is not None else None

                srv = RawDiscoveredService(
                    protocol=protocol,
                    port=port_num,
                    service_name=service_name,
                    product=product,
                    version=version,
                    extra_info=extra_info,
                    state=state,
                )
                discovered_services.append(srv)

                # Check script outputs for vulnerability findings
                for script_elem in port_elem.findall("script"):
                    finding = _script_finding(
                        script_elem, ip_addr or hostname or "unknown", port_num, protocol.value
                    )
                    if finding:
                        result.findings.append(finding)

        # Host-level scripts (e.g. smb-vuln-*) are reported under <hostscript>
        for script_elem in host_elem.findall("hostscript/script"):
            finding = _script_finding(script_elem, ip_addr or hostname or "unknown", None, None)
            if finding:
                result.findings.append(finding)

        asset = RawDiscoveredAsset(
            asset_type=asset_type,
            ip_address=ip_addr,
            hostname=hostname,
            os_name=os_name,
            os_confidence=os_accuracy,
            services=discovered_services,
        )
        result.assets.append(asset)

    return result
