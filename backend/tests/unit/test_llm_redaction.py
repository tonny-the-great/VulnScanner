"""Scanner text is redacted before it is sent to a third-party LLM."""

import json
import time

import pytest

from app.llm.prompts import build_remediation_prompt, redact_for_llm, replace_known_identifiers

ASSET_IDENTIFIERS = ("10.20.30.40", "web01", "payroll.example.com")

NMAP_OUTPUT = """
ssl-heartbleed:
  VULNERABLE:
  The Heartbleed Bug in OpenSSL 1.0.2k (CVE-2014-0160, CWE-310) allows reading memory over TLSv1.2.
  Host: WEB01 (10.20.30.40) also answers as payroll.example.com and backup.internal.corp
  Peer 172.16.5.9 and fe80::1c2d:3e4f%eth0, gateway MAC 00:1A:2B:3C:4D:5E
  Set-Cookie: SESSIONID=0123456789abcdef0123456789abcdef; Secure
  Authorization: Basic YWRtaW46c2VjcmV0
  Contact: ops-team@example.org, see https://intranet.example.org/wiki?page=tls
  csrf_token=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==
"""

LEAKS = (
    "10.20.30.40", "web01", "WEB01", "payroll", "example.com", "backup.internal.corp", "172.16.5.9",
    "fe80::1c2d:3e4f", "00:1A:2B:3C:4D:5E", "0123456789abcdef0123456789abcdef", "YWRtaW46c2VjcmV0",
    "ops-team@example.org", "intranet.example.org", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg",
)
KEPT = ("CVE-2014-0160", "CWE-310", "OpenSSL 1.0.2k", "TLSv1.2", "Heartbleed")


def context_of(prompt):
    return json.loads(prompt.split("\n\n", 1)[1])


def build(**overrides):
    values = {
        "title": "Heartbleed on web01",
        "description": NMAP_OUTPUT,
        "severity": "high",
        "cve_ids": ["CVE-2014-0160"],
        "cwe_ids": ["CWE-310"],
        "port": 443,
        "protocol": "tcp",
        "service_product": "OpenSSL 1.0.2k",
        "source_tool": "nmap",
        "scanner_reference": "ssl-heartbleed@payroll.example.com",
        "known_identifiers": ASSET_IDENTIFIERS,
    }
    values.update(overrides)
    return build_remediation_prompt(**values)


def test_prompt_contains_no_private_identifiers():
    prompt = build()
    for leak in LEAKS:
        assert leak.lower() not in prompt.lower(), leak
    for kept in KEPT:
        assert kept in prompt, kept
    context = context_of(prompt)
    assert context["title"] == "Heartbleed on [asset]"
    assert context["source_tool"] == "nmap"
    assert context["scanner_reference"] == "ssl-heartbleed@[asset]"
    assert "[redacted]" in context["description"]
    assert "[ip]" in context["description"] and "[mac]" in context["description"]
    assert "[url]" in context["description"] and "[email]" in context["description"]


@pytest.mark.parametrize(
    ("source_tool", "limit"), [("nmap", 600), ("testssl", 600), ("nuclei", 1500)]
)
def test_description_length_depends_on_source(source_tool, limit):
    description = "Weak cipher suites are offered by the service. " * 100
    context = context_of(build(description=description, source_tool=source_tool))
    assert len(context["description"]) == limit
    assert context["description"].endswith("...")


def test_redaction_keeps_vulnerability_and_version_strings():
    text = (
        "CVE-2014-0160 CWE-310 OpenSSL 1.0.2k TLSv1.2 TLSv1.3 Apache httpd 2.4.49 "
        "OpenSSH 7.4p1 nginx.conf"
    )
    assert redact_for_llm(text) == text


@pytest.mark.parametrize(("text", "expected"), [
    ("Cookie: a=b; c=d", "Cookie: [redacted]"),
    ("proxy-authorization: Digest abc", "proxy-authorization: [redacted]"),
    ("X-Api-Key: 1234", "X-Api-Key: [redacted]"),
    ("password=hunter2 user=bob", "password=[redacted] user=bob"),
    ("see http://10.0.0.5:8080/admin now", "see [url] now"),
    ("mail root@mail.example.net", "mail [email]"),
    ("addresses 192.168.0.1 and [2001:db8::7]:443", "addresses [ip] and [ip]:443"),
    ("version 999.1.2.3 is not an address", "version 999.1.2.3 is not an address"),
    ("at 12:30:45 UTC", "at 12:30:45 UTC"),
    ("host db-01.corp.local responded", "host [host] responded"),
    ("digest 5f4dcc3b5aa765d61d8327deb882cf99", "digest [redacted]"),
    ("path /var/lib/postgresql/14/main/pg.conf", "path /var/lib/postgresql/14/main/pg.conf"),
    ('{"password": "hunter2"}', '{"password": "[redacted]"}'),
    ('password="hunter2"', 'password="[redacted]"'),
    ("api_key: 'sk-live-abc'", "api_key: '[redacted]'"),
])
def test_redaction_rules(text, expected):
    assert redact_for_llm(text) == expected


def test_known_identifiers_are_exact_and_case_insensitive():
    identifiers = ("10.0.0.1", "Web01")
    replaced = replace_known_identifiers("WEB01 and web01.corp at 10.0.0.1:22", identifiers)
    assert replaced == "[asset] and [asset] at [asset]:22"
    # A longer address is a different host: not [asset], but still removed.
    assert redact_for_llm("neighbour 10.0.0.12", identifiers) == "neighbour [ip]"
    # Words merely containing a short identifier are left alone.
    assert replace_known_identifiers("mongodb", ("db",)) == "mongodb"


@pytest.mark.parametrize(
    "run", ["a." * 25_000, "1." * 25_000, "a" * 50_000], ids=["labels", "digits", "letters"]
)
def test_pathological_input_is_bounded_before_redaction(run):
    started = time.perf_counter()
    redact_for_llm(run, max_chars=600)
    assert time.perf_counter() - started < 1.0


def test_input_cut_never_leaves_a_partial_address():
    # The bounded input ends on a word boundary: the trailing address is either
    # whole (and redacted) or dropped, never cut to a leftover fragment.
    text = "\n" * 1795 + "10.20.30.40"  # the 1800-character cut falls inside the address
    assert redact_for_llm(text, max_chars=600) is None
    assert redact_for_llm("x " * 600 + "10.20.30.40", max_chars=600).endswith("...")


def test_empty_and_whitespace_text():
    assert redact_for_llm(None) is None
    assert redact_for_llm("") is None
    assert redact_for_llm(" \n\t ") is None
    assert redact_for_llm("a\n\n   b\tc") == "a b c"
    assert context_of(build(description=None))["description"] == "No description provided"
