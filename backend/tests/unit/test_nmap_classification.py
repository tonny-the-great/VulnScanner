"""Nmap script results are classified by what the script actually reported."""

from xml.sax.saxutils import quoteattr

from app.models.finding import FindingConfidence, FindingSeverity
from app.scanning.adapters.nmap.parser import parse_nmap_xml


def _parse(
    tmp_path,
    scripts: list[tuple[str, str]],
    runstats: str = '<runstats><hosts up="1" down="0" total="1"/></runstats>',
):
    port_scripts = "".join(
        f"<script id={quoteattr(sid)} output={quoteattr(out)}/>" for sid, out in scripts
    )
    xml = (
        '<?xml version="1.0"?><nmaprun>'
        '<host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/>'
        f"{port_scripts}"
        "</port></ports></host>"
        f"{runstats}</nmaprun>"
    )
    path = tmp_path / "nmap.xml"
    path.write_text(xml, encoding="utf-8")
    result = parse_nmap_xml(str(path), 0, "", "", 0)
    assert result.error_message is None
    return result


HEARTBLEED = """
  VULNERABLE:
  The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic library.
    State: VULNERABLE
    Risk factor: High
      OpenSSL versions 1.0.1 and 1.0.2-beta releases are vulnerable.
    References:
      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
"""


def test_vulns_library_state_vulnerable_with_risk_factor(tmp_path):
    [finding] = _parse(tmp_path, [("ssl-heartbleed", HEARTBLEED)]).findings
    assert finding.title == "Nmap: ssl-heartbleed on port 443/tcp"
    assert finding.confidence == FindingConfidence.CONFIRMED
    assert finding.severity == FindingSeverity.HIGH
    assert finding.cve_ids == ["CVE-2014-0160"]


def test_vulns_library_likely_and_not_vulnerable(tmp_path):
    result = _parse(tmp_path, [
        ("ssl-poodle", "State: NOT VULNERABLE\n  IDs: CVE:CVE-2014-3566"),
        ("http-slowloris-check", "State: LIKELY VULNERABLE\n  Risk factor: Low"),
    ])
    [finding] = result.findings
    assert finding.scanner_reference == "http-slowloris-check"
    assert finding.confidence == FindingConfidence.LIKELY
    assert finding.severity == FindingSeverity.LOW


def test_not_vulnerable_entries_do_not_leak_into_reported_ones(tmp_path):
    output = (
        "VULNERABLE:\n"
        "  A\n    State: VULNERABLE\n    IDs: CVE:CVE-2020-0001\n    Risk factor: Medium\n"
        "  B\n    State: NOT VULNERABLE\n    IDs: CVE:CVE-2020-0002\n    Risk factor: Critical\n"
    )
    [finding] = _parse(tmp_path, [("smb-vuln-multi", output)]).findings
    assert finding.cve_ids == ["CVE-2020-0001"]
    assert finding.severity == FindingSeverity.MEDIUM


def test_ssl_enum_ciphers_grades(tmp_path):
    result = _parse(
        tmp_path, [("ssl-enum-ciphers", "TLSv1.2:\n  ciphers: ...\n|_  least strength: A")]
    )
    assert result.findings == []
    [finding] = _parse(
        tmp_path, [("ssl-enum-ciphers", "TLSv1.0:\n  ciphers: ...\n|_  least strength: C")]
    ).findings
    assert finding.confidence == FindingConfidence.CONFIRMED
    assert finding.severity == FindingSeverity.MEDIUM
    [finding] = _parse(tmp_path, [("ssl-enum-ciphers", "SSLv3:\n|_  least strength: F")]).findings
    assert finding.severity == FindingSeverity.HIGH


def test_http_security_headers_is_informational(tmp_path):
    [finding] = _parse(
        tmp_path, [("http-security-headers", "Strict_Transport_Security:\n  HSTS not configured")]
    ).findings
    assert finding.severity == FindingSeverity.INFO
    assert finding.confidence == FindingConfidence.CONFIRMED


def test_vulners_is_unverified_and_scored_by_highest_cvss(tmp_path):
    output = (
        "cpe:/a:openbsd:openssh:8.9p1:\n"
        "    \tCVE-2023-38408\t9.8\thttps://vulners.com/cve/CVE-2023-38408\n"
        "    \tCVE-2023-28531\t9.8\thttps://vulners.com/cve/CVE-2023-28531\n"
        "    \tCVE-2021-41617\t7.0\thttps://vulners.com/cve/CVE-2021-41617\n"
        "    \tPACKETSTORM:173661\t9.8\thttps://vulners.com/packetstorm/PACKETSTORM:173661\t*EXPLOIT*\n"
    )
    [finding] = _parse(tmp_path, [("vulners", output)]).findings
    assert finding.confidence == FindingConfidence.UNVERIFIED
    assert finding.severity == FindingSeverity.CRITICAL
    assert finding.cvss_score == 9.8
    assert finding.cve_ids == ["CVE-2021-41617", "CVE-2023-28531", "CVE-2023-38408"]


def test_vulners_without_cves_is_not_a_finding(tmp_path):
    output = "cpe:/a:example:thing:1.0:\n    \tSSV:12345\t5.0\thttps://vulners.com/seebug/SSV:12345\n"
    assert _parse(tmp_path, [("vulners", output)]).findings == []


def test_legacy_markers_and_unrelated_scripts(tmp_path):
    result = _parse(tmp_path, [
        ("fixture-vuln", "VULNERABLE CVE-2025-12345"),
        ("old-cve-check", "NOT VULNERABLE"),
        ("other-vuln-check", "Possible issue found"),
        ("http-title", "Site VULNERABLE to nothing; just a title"),
        ("banner", "SSH-2.0-OpenSSH_8.9"),
    ])
    by_ref = {f.scanner_reference: f for f in result.findings}
    assert set(by_ref) == {"fixture-vuln", "other-vuln-check"}
    assert by_ref["fixture-vuln"].confidence == FindingConfidence.CONFIRMED
    assert by_ref["fixture-vuln"].severity == FindingSeverity.HIGH
    assert by_ref["fixture-vuln"].cve_ids == ["CVE-2025-12345"]
    assert by_ref["other-vuln-check"].confidence == FindingConfidence.LIKELY
    assert by_ref["other-vuln-check"].severity == FindingSeverity.MEDIUM


def test_runstats_warnings(tmp_path):
    result = _parse(
        tmp_path, [], runstats='<runstats><hosts up="0" down="4" total="4"/></runstats>'
    )
    assert result.warnings == ["No hosts responded to nmap; results are incomplete"]
    result = _parse(
        tmp_path, [], runstats='<runstats><hosts up="1" down="3" total="4"/></runstats>'
    )
    assert result.warnings == ["3 of 4 addresses did not respond"]
    assert _parse(tmp_path, []).warnings == []


def test_truncated_xml_has_no_runstats_warning(tmp_path):
    path = tmp_path / "nmap.xml"
    path.write_text('<?xml version="1.0"?><nmaprun><host><status state="up"/>', encoding="utf-8")
    result = parse_nmap_xml(str(path), 0, "", "", 0)
    assert result.error_message
    assert result.warnings == []
