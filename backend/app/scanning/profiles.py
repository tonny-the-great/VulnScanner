"""
Scan profile definitions and default templates.

Profiles are enforced server-side. Users cannot inject arbitrary
command-line flags or override scanner parameters outside the profile schema.
"""

from __future__ import annotations

from typing import Any

DEFAULT_PROFILES: list[dict[str, Any]] = [
    {
        "name": "fast_discovery",
        "display_name": "Fast Discovery",
        "description": (
            "Fast top-100 port scan with service banner discovery "
            "and asset enumeration."
        ),
        "requires_confirmation": False,
        "is_intrusive": False,
        "config_json": {
            "nmap": {
                "top_ports": 100,
                "timing": 4,
                "service_detection": True,
                "os_detection": False,
                "scripts": ["banner"],
            },
            "nuclei": {
                "enabled": False,
            },
            "testssl": {
                "enabled": False,
            },
        },
    },
    {
        "name": "standard_network",
        "display_name": "Standard Network Scan",
        "description": (
            "Top-1000 ports with version detection "
            "and safe Nmap default discovery scripts."
        ),
        "requires_confirmation": False,
        "is_intrusive": False,
        "config_json": {
            "nmap": {
                "top_ports": 1000,
                "timing": 3,
                "service_detection": True,
                "os_detection": True,
                "scripts": ["default", "discovery"],
            },
            "nuclei": {
                "enabled": False,
            },
            "testssl": {
                "enabled": False,
            },
        },
    },
    {
        "name": "ssl_tls_audit",
        "display_name": "SSL/TLS Security Audit",
        "description": (
            "Exhaustive SSL/TLS configuration, certificate validation, "
            "and cipher suite evaluation."
        ),
        "requires_confirmation": False,
        "is_intrusive": False,
        "config_json": {
            "nmap": {
                "enabled": False,
            },
            "nuclei": {
                "enabled": True,
                "tags": ["ssl", "tls"],
                "severity": ["critical", "high", "medium", "low"],
            },
            "testssl": {
                "enabled": True,
                "checks": ["protocols", "ciphers", "vulnerabilities"],
            },
        },
    },
    {
        "name": "web_vuln_scan",
        "display_name": "Web Application Vulnerability Scan",
        "description": (
            "Nuclei-driven vulnerability scan covering OWASP top 10, "
            "known CVEs, and security misconfigurations."
        ),
        "requires_confirmation": False,
        "is_intrusive": False,
        "config_json": {
            "nmap": {
                "enabled": False,
            },
            "nuclei": {
                "enabled": True,
                "tags": ["cve", "misconfig", "exposure", "owasp"],
                "severity": ["critical", "high", "medium"],
                "rate_limit": 150,
            },
            "testssl": {
                "enabled": False,
            },
        },
    },
    {
        "name": "comprehensive",
        "display_name": "Comprehensive Assessment",
        "description": (
            "Full workflow: Nmap service discovery "
            "followed by targeted Nuclei and testssl assessments."
        ),
        "requires_confirmation": True,
        "is_intrusive": False,
        "config_json": {
            "nmap": {
                "top_ports": 1000,
                "timing": 3,
                "service_detection": True,
                "os_detection": True,
                "scripts": ["default", "vuln"],
            },
            "nuclei": {
                "enabled": True,
                "tags": ["cve", "misconfig", "exposure", "vuln"],
                "severity": ["critical", "high", "medium", "low"],
                "rate_limit": 100,
            },
            "testssl": {
                "enabled": True,
                "checks": ["protocols", "vulnerabilities"],
            },
        },
    },
    {
        "name": "intrusive_active",
        "display_name": "Active Penetration Testing (Intrusive)",
        "description": (
            "Intrusive vulnerability verification with active payload delivery. "
            "Requires explicit acknowledgement."
        ),
        "requires_confirmation": True,
        "is_intrusive": True,
        "config_json": {
            "nmap": {
                "top_ports": 5000,
                "timing": 3,
                "service_detection": True,
                # vuln_intrusive allows intrusive vuln checks; dos/brute/fuzzer stay excluded.
                "scripts": ["default", "discovery", "vuln_intrusive"],
            },
            "nuclei": {
                "enabled": True,
                "tags": ["cve", "rce", "sqli", "lfi", "auth-bypass", "takeover"],
                "severity": ["critical", "high", "medium", "low"],
                "rate_limit": 50,
            },
            "testssl": {
                "enabled": True,
            },
        },
    },
]
