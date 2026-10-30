"""Missing and corrupt scanner output must not look like a clean assessment."""

import pytest

from app.scanning.adapters.nmap.parser import parse_nmap_xml
from app.scanning.adapters.nuclei.parser import parse_nuclei_jsonl
from app.scanning.adapters.testssl.parser import parse_testssl_json


@pytest.mark.parametrize("parser", [parse_nmap_xml, parse_nuclei_jsonl, parse_testssl_json])
def test_missing_output_is_an_error(parser, tmp_path):
    assert parser(str(tmp_path / "missing"), 0, "", "", 0).error_message


def test_empty_nuclei_output_can_be_a_clean_run(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    result = parse_nuclei_jsonl(str(path), 0, "", "", 0)
    assert result.error_message is None
    assert result.findings == []


def test_invalid_nuclei_json_is_an_error(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_text("{invalid}", encoding="utf-8")
    assert parse_nuclei_jsonl(str(path), 0, "", "", 0).error_message


def test_testssl_flat_json_is_parsed(tmp_path):
    path = tmp_path / "testssl.json"
    path.write_text(
        '[{"id": "SSLv3", "ip": "example.test/192.0.2.10", "port": "443", "severity": "HIGH",'
        ' "cve": "CVE-2014-3566 CVE-2014-8730", "cwe": "CWE-310", "finding": "offered"},'
        ' {"id": "TLS1_3", "ip": "example.test/192.0.2.10", "port": "443", "severity": "OK",'
        ' "finding": "offered"}]',
        encoding="utf-8",
    )
    result = parse_testssl_json(str(path), 0, "", "", 0)
    assert result.error_message is None
    [finding] = result.findings
    assert finding.target_address == "192.0.2.10"
    assert finding.title == "SSL/TLS: SSLv3"
    assert finding.cve_ids == ["CVE-2014-3566", "CVE-2014-8730"]


def test_nmap_keeps_hosts_from_truncated_xml_and_reads_host_scripts(tmp_path):
    from app.models.finding import FindingConfidence

    path = tmp_path / "nmap.xml"
    path.write_text(
        '<?xml version="1.0"?><nmaprun>'
        '<host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="443"><state state="open"/>'
        '<script id="http-vuln-cve2017-5638" output="State: NOT VULNERABLE"/></port></ports>'
        '<hostscript><script id="smb-vuln-ms17-010" output="State: VULNERABLE CVE-2017-0143"/>'
        "</hostscript>"
        '</host><host><status state="up"/>',  # cut off mid-host, as after a timeout
        encoding="utf-8",
    )
    result = parse_nmap_xml(str(path), 0, "", "", 0)
    assert result.error_message  # truncation is still reported
    assert [a.ip_address for a in result.assets] == ["192.0.2.5"]
    by_ref = {f.scanner_reference: f for f in result.findings}
    assert "http-vuln-cve2017-5638" not in by_ref  # "State: NOT VULNERABLE" is not a finding
    assert by_ref["smb-vuln-ms17-010"].confidence == FindingConfidence.CONFIRMED
    assert by_ref["smb-vuln-ms17-010"].port is None


def test_nuclei_tolerates_odd_lines(tmp_path):
    path = tmp_path / "nuclei.jsonl"
    path.write_text(
        "[1, 2]\n"
        '{"template-id": "x", "host": "https://example.test",'
        ' "info": {"name": "X", "severity": "low",'
        ' "classification": {"cvss-score": "N/A"}}}\n',
        encoding="utf-8",
    )
    result = parse_nuclei_jsonl(str(path), 0, "", "", 0)
    assert len(result.findings) == 1
    assert result.findings[0].cvss_score is None
