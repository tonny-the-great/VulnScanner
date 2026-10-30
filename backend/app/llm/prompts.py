"""
LLM prompt templates for vulnerability remediation.

CRITICAL SECURITY RULE:
Only whitelisted finding fields are sent to an LLM, and free text from scanners
is redacted before it leaves the platform. Evidence rows, remediation notes,
internal ids and organization data are never sent.

What build_remediation_prompt() sends:
  - title: the affected asset's own identifiers (IP address, hostname, domain)
    are replaced with "[asset]".
  - description: always passed through redact_for_llm(). It removes the asset's
    identifiers, credential-bearing header values (Cookie, Set-Cookie,
    Authorization, Proxy-Authorization, X-Api-Key) and key=value secrets, URLs,
    e-mail addresses, IP and MAC addresses, host names and long token-like
    strings, then collapses whitespace and truncates. Nuclei descriptions come
    from public template text and keep up to 1500 characters; other scanners'
    output (e.g. raw Nmap script output) keeps at most 600.
  - scanner_reference: redacted the same way.
  - severity, CVE/CWE ids, port, protocol, detected product/version and the
    source tool name are sent as they are.

Passwords, tokens, session IDs, internal org IDs and private server evidence
must NEVER be included in LLM prompts.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable

ASSET_PLACEHOLDER = "[asset]"
REDACTED_PLACEHOLDER = "[redacted]"

DEFAULT_REDACTION_MAX_CHARS = 600
# Nuclei descriptions are public template text, so more of it is kept.
NUCLEI_DESCRIPTION_MAX_CHARS = 1500
SCANNER_REFERENCE_MAX_CHARS = 200
# Input is cut to this multiple of max_chars before redaction (see redact_for_llm).
_PRE_REDACTION_FACTOR = 3
_TRAILING_TOKEN_RE = re.compile(r"\S+\Z")
# Shorter identifiers would replace parts of ordinary words.
_MIN_IDENTIFIER_LENGTH = 3

# Header lines whose values are credentials: the rest of the line is dropped.
_SENSITIVE_HEADER_RE = re.compile(
    r"\b(set-cookie|cookie|proxy-authorization|authorization|x-api-key)[ \t]*:[^\r\n]*",
    re.IGNORECASE,
)
# key=value / key: value pairs whose value is a secret (password=..., PHPSESSID=..., api_key: ...),
# including quoted and JSON forms ('"password": "x"', 'password="x"').
_SECRET_ASSIGNMENT_RE = re.compile(
    r"\b(\w*(?:passw(?:or)?d|pwd|secret|token|api[-_]?key|access[-_]?key|sess(?:ion)?[-_]?id))"
    r"([\"']?[ \t]*[=:][ \t]*[\"']?)"
    r"(?!\[redacted\])[^\s;,&'\"]+",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"\b[a-z][a-z0-9+.-]{1,15}://[^\s<>\"'`]+", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
# MAC addresses (6 pairs) and longer colon/dash separated hex fingerprints (SSH host keys)
_HEX_PAIRS_RE = re.compile(r"(?<![\w:.-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5,}(?![\w:-])")
# Space separated hex fingerprints, as Nmap prints certificate digests ("SHA-1: 5a1b 2c3d ...")
_HEX_GROUPS_RE = re.compile(r"(?<!\w)[0-9A-Fa-f]{4}(?: [0-9A-Fa-f]{4}){4,}(?!\w)")
# IPv6 candidates (validated with ipaddress), optionally bracketed and with a zone id
_IPV6_ADDRESS = r"(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4})"
_IPV6_CANDIDATE_RE = re.compile(
    rf"(?<![\w:.])(?:\[({_IPV6_ADDRESS})(?:%[\w.-]+)?\]|({_IPV6_ADDRESS})(?:%[\w.-]+)?(?![\w:]))"
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
_LONG_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_RE = re.compile(r"[0-9A-Fa-f]+")
# Two or more DNS labels ending in an alphabetic top-level label
_HOSTNAME_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63})(?![A-Za-z0-9-])"
)
# File names look like host names ("nginx.conf"); these suffixes are not public TLDs.
_FILE_SUFFIXES = frozenset({
    "asp", "aspx", "bak", "bat", "bin", "cer", "cfg", "cgi", "class", "cmd", "cnf", "conf",
    "config", "crt", "csr", "css", "db", "deb", "der", "dll", "dmg", "ear", "env", "exe",
    "gz", "htm", "html", "img", "ini", "iso", "jar", "js", "jsp", "json", "key", "lock",
    "log", "mjs", "msi", "nse", "old", "pem", "php", "phtml", "pid", "pkg", "properties",
    "rb", "rpm", "service", "sock", "sql", "sqlite", "tar", "tgz", "tmp", "ts", "txt",
    "war", "xhtml", "xml", "yaml", "yml",
})
# Product names that look like host names
_PRODUCT_NAMES = frozenset({"asp.net", "ado.net", "socket.io"})


# Labels joined to a replaced identifier ("payroll.[asset]", "[asset].corp") name the
# asset too and are folded into the placeholder.
_ASSET_PREFIX_LABELS_RE = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+\[asset\]"
)
_ASSET_SUFFIX_LABELS_RE = re.compile(r"\[asset\](?:\.(?:[A-Za-z0-9-]+|\[asset\]))+(?![A-Za-z0-9-])")


def _identifier_pattern(identifier: str) -> re.Pattern[str]:
    # Not part of a longer word or number: "10.0.0.1" must not match inside "10.0.0.12".
    return re.compile(
        rf"(?<![A-Za-z0-9]){re.escape(identifier)}(?![A-Za-z0-9])",
        re.IGNORECASE,
    )


def replace_known_identifiers(text: str, known_identifiers: Iterable[str | None] = ()) -> str:
    """Replace case-insensitive occurrences of the asset's own identifiers with '[asset]'."""
    identifiers = {
        value.strip()
        for value in known_identifiers
        if value and len(value.strip()) >= _MIN_IDENTIFIER_LENGTH
    }
    # Longest first, so "web01.example.com" is replaced before "example.com".
    for identifier in sorted(identifiers, key=len, reverse=True):
        text = _identifier_pattern(identifier).sub(ASSET_PLACEHOLDER, text)
    if ASSET_PLACEHOLDER in text:
        text = _ASSET_PREFIX_LABELS_RE.sub(ASSET_PLACEHOLDER, text)
        text = _ASSET_SUFFIX_LABELS_RE.sub(ASSET_PLACEHOLDER, text)
    return text


def _replace_hex_pairs(match: re.Match[str]) -> str:
    return "[mac]" if len(match.group(0)) == 17 else REDACTED_PLACEHOLDER


def _replace_hex_groups(match: re.Match[str]) -> str:
    value = match.group(0)
    # Runs of four-digit decimal numbers (years, ports) are not fingerprints.
    return REDACTED_PLACEHOLDER if re.search(r"[A-Fa-f]", value) else value


def _replace_ipv6(match: re.Match[str]) -> str:
    try:
        ipaddress.IPv6Address(match.group(1) or match.group(2))
    except ValueError:
        return match.group(0)  # e.g. a time such as 12:30:45
    return "[ip]"


def _replace_ipv4(match: re.Match[str]) -> str:
    if all(int(octet) <= 255 for octet in match.group(0).split(".")):
        return "[ip]"
    return match.group(0)


def _replace_long_token(match: re.Match[str]) -> str:
    token = match.group(0)
    core = token.rstrip("=")
    if _HEX_RE.fullmatch(core):
        return REDACTED_PLACEHOLDER  # hashes, session ids, keys
    if "/" in core and all(len(segment) < 24 for segment in core.split("/")):
        return token  # a file path such as /var/lib/postgresql/14/main
    if any(char.isdigit() for char in core) and any(char.isalpha() for char in core):
        return REDACTED_PLACEHOLDER  # base64 or random alphanumeric secrets
    return token  # a long ordinary word


def _replace_hostname(match: re.Match[str]) -> str:
    value = match.group(0)
    if match.group(1).lower() in _FILE_SUFFIXES or value.lower() in _PRODUCT_NAMES:
        return value
    return "[host]"


def redact_for_llm(
    text: str | None,
    known_identifiers: Iterable[str | None] = (),
    max_chars: int = DEFAULT_REDACTION_MAX_CHARS,
) -> str | None:
    """
    Remove identifying and secret data from scanner text before it is sent to an LLM.

    Replaces the asset's identifiers with [asset], credential header values and
    key=value secrets with [redacted], URLs with [url], e-mail addresses with
    [email], IP addresses with [ip], MAC addresses with [mac], host names with
    [host] and long hex/base64 runs with [redacted]. Vulnerability ids (CVE-2014-0160,
    CWE-310), product versions (OpenSSL 1.0.2k) and protocol names (TLSv1.2) are
    kept. Whitespace is collapsed and the result truncated to max_chars.
    Returns None when nothing is left.
    """
    if not text:
        return None
    # Several patterns are super-linear on long pathological runs, and scanner
    # text is controlled by the scan target: bound the input before any regex
    # runs. The cut falls on whitespace so no partial address or token survives.
    limit = max(max_chars, 1) * _PRE_REDACTION_FACTOR
    if len(text) > limit:
        head = text[:limit]
        if not text[limit].isspace():
            head = _TRAILING_TOKEN_RE.sub("", head)
        text = head
    # Line-based rules first, before whitespace is collapsed.
    redacted = _SENSITIVE_HEADER_RE.sub(lambda m: f"{m.group(1)}: {REDACTED_PLACEHOLDER}", text)
    redacted = _SECRET_ASSIGNMENT_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{REDACTED_PLACEHOLDER}", redacted
    )
    redacted = replace_known_identifiers(redacted, known_identifiers)
    redacted = _URL_RE.sub("[url]", redacted)
    redacted = _EMAIL_RE.sub("[email]", redacted)
    redacted = _HEX_PAIRS_RE.sub(_replace_hex_pairs, redacted)
    redacted = _HEX_GROUPS_RE.sub(_replace_hex_groups, redacted)
    redacted = _IPV6_CANDIDATE_RE.sub(_replace_ipv6, redacted)
    redacted = _IPV4_RE.sub(_replace_ipv4, redacted)
    redacted = _LONG_TOKEN_RE.sub(_replace_long_token, redacted)
    redacted = _HOSTNAME_RE.sub(_replace_hostname, redacted)

    collapsed = " ".join(redacted.split())
    if not collapsed:
        return None
    if len(collapsed) > max_chars:
        if max_chars <= 3:
            return collapsed[:max_chars]
        collapsed = collapsed[: max_chars - 3].rstrip() + "..."
    return collapsed


SYSTEM_PROMPT = """You are an expert security engineer and remediation consultant.
Your task is to provide clear, actionable, production-ready remediation guidance for a
discovered vulnerability. The guidance should be accessible to a system administrator who is
not a full-time security specialist.
Placeholders such as [asset], [host], [ip], [url] and [redacted] stand for details withheld
for privacy; keep them as placeholders.

You MUST respond strictly with a valid JSON object matching this schema:
{
  "summary": "Brief summary of the issue and why it matters (2-3 sentences)",
  "root_cause": "The technical root cause of the vulnerability",
  "business_impact": "Operational, regulatory, or business risk if left unaddressed",
  "prerequisites": ["Prerequisites or backups needed before applying fix"],
  "remediation_steps": [
    {
      "step_number": 1,
      "title": "Short title of step",
      "description": "Clear step explanation",
      "commands_or_code": "Optional exact command, configuration snippet, or code patch (or null)",
      "verification": "How to verify this step succeeded"
    }
  ],
  "verification_steps": ["High-level tests to verify the system is secured and functional"],
  "references": ["Official documentation, CVE links, or security advisories"]
}
Do not include any conversational filler, markdown code fence blocks, or text outside the
JSON object.
"""


def build_remediation_prompt(
    title: str,
    description: str | None,
    severity: str,
    cve_ids: list[str],
    cwe_ids: list[str],
    port: int | None,
    protocol: str | None,
    service_product: str | None,
    source_tool: str | None = None,
    scanner_reference: str | None = None,
    known_identifiers: Iterable[str | None] = (),
) -> str:
    """Construct the redacted context for the LLM prompt (see the module docstring)."""
    identifiers = tuple(known_identifiers)
    description_limit = (
        NUCLEI_DESCRIPTION_MAX_CHARS
        if (source_tool or "").lower() == "nuclei"
        else DEFAULT_REDACTION_MAX_CHARS
    )
    context = {
        "title": replace_known_identifiers(title, identifiers),
        "description": redact_for_llm(description, identifiers, max_chars=description_limit)
        or "No description provided",
        "severity": severity,
        "source_tool": source_tool,
        "scanner_reference": redact_for_llm(
            scanner_reference, identifiers, max_chars=SCANNER_REFERENCE_MAX_CHARS
        ),
        "cve_ids": cve_ids,
        "cwe_ids": cwe_ids,
        "port": port,
        "protocol": protocol,
        "service_detected": replace_known_identifiers(service_product, identifiers)
        if service_product
        else None,
    }
    payload = json.dumps(context, indent=2)
    return f"Please provide remediation guidance for the following vulnerability:\n\n{payload}"
