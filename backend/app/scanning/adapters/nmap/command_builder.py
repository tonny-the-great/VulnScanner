"""Nmap command builder with strict parameter sanitization."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

from app.config import get_settings
from app.core.exceptions import ValidationError
from app.models.authorization import TargetType
from app.scanning.target_validator import validate_and_normalize_target

# Profile script keys map to vetted NSE boolean expressions. Profiles never name
# scripts or categories directly, so a typo or "all" cannot widen what runs.
NSE_SCRIPT_SETS: dict[str, str] = {
    "banner": "banner",
    "default": "default",
    "safe": "safe",
    "discovery": "(discovery and safe)",
    "vuln": "(vuln and safe)",
    "vuln_intrusive": "vuln",
}
# Never run, whatever the profile: denial of service, credential guessing, fuzzing,
# broadcast traffic beyond the authorized targets, and calls to third-party services.
# Consequences, by design: vulners (category "external": it sends detected product
# versions to vulners.com) never runs, and ssl-enum-ciphers ("discovery, intrusive")
# is in none of the script sets above. The parser still classifies both should this
# policy change; TLS cipher grading comes from testssl.sh instead.
NSE_ALWAYS_EXCLUDED = ("dos", "brute", "fuzzer", "broadcast", "external")
NSE_SCRIPT_TIMEOUT = "10m"
OS_DETECTION_SKIPPED_WARNING = (
    "OS detection skipped: nmap is not running with raw-socket privileges "
    "(set NMAP_PRIVILEGED=true when the worker has CAP_NET_RAW)"
)


def build_script_expression(script_keys: Any, intrusive: bool) -> str | None:
    """Translate profile script keys into one NSE expression, or None when no scripts run."""
    if not script_keys:
        return None
    if not isinstance(script_keys, (list, tuple)):
        raise ValidationError("Nmap scripts must be a list of script set names")
    expressions: list[str] = []
    for key in script_keys:
        expression = NSE_SCRIPT_SETS.get(key) if isinstance(key, str) else None
        if expression is None:
            raise ValidationError(f"Unknown Nmap script set '{key}'")
        if expression not in expressions:
            expressions.append(expression)
    excluded = list(NSE_ALWAYS_EXCLUDED)
    if not intrusive:
        excluded.append("intrusive")
    return f"({' or '.join(expressions)}) and not ({' or '.join(excluded)})"


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def build_nmap_command(
    targets: list[str],
    config: dict[str, Any],
    output_xml_path: str,
    warnings: list[str] | None = None,
) -> list[str]:
    """
    Construct safe arguments for Nmap execution.

    Never uses shell string interpolation. Only approved flags derived
    from the profile configuration are added. Options that cannot run in this
    environment are skipped and explained in ``warnings`` when a list is given.
    """
    if not targets:
        raise ValidationError("No targets provided for Nmap scan")

    # Validate each target
    normalized_targets: list[str] = []
    target_types: set[TargetType] = set()
    for t in targets:
        target_type, norm = validate_and_normalize_target(t)
        if target_type == TargetType.URL:
            # Nmap scans hosts, not URLs
            target_type, norm = validate_and_normalize_target(urlparse(norm).hostname or "")
        if norm not in normalized_targets:
            normalized_targets.append(norm)
        target_types.add(target_type)

    ipv6_types = {TargetType.IPV6, TargetType.IPV6_CIDR}
    if target_types & ipv6_types and target_types - ipv6_types:
        raise ValidationError(
            "Nmap cannot scan IPv4/hostname and IPv6 targets in one run; use separate scans"
        )

    cmd = ["nmap", "-oX", output_xml_path, "--noninteractive"]
    if target_types <= ipv6_types:
        cmd.append("-6")

    # Single hosts were authorized explicitly, so scan them even when they ignore
    # ping probes; ranges keep host discovery so dead addresses are not port-scanned.
    has_range = bool(target_types & {TargetType.IPV4_CIDR, TargetType.IPV6_CIDR})
    if not has_range and config.get("host_discovery") is not True:
        cmd.append("-Pn")

    # Timing template (-T1 through -T5, default T3)
    timing = config.get("timing", 3)
    if timing not in (1, 2, 3, 4, 5):
        timing = 3
    cmd.append(f"-T{timing}")

    # Port configuration
    top_ports = config.get("top_ports")
    specific_ports = config.get("ports")
    if specific_ports:
        # Validate format e.g. "80,443,8080" or "1-1000"
        if not re.match(r"^[0-9,\-]+$", str(specific_ports)):
            raise ValidationError("Invalid port specification")
        cmd.extend(["-p", str(specific_ports)])
    elif top_ports:
        ports_val = int(top_ports)
        if ports_val not in (10, 100, 1000, 5000, 10000):
            ports_val = 100
        cmd.extend(["--top-ports", str(ports_val)])

    # Service version detection
    if config.get("service_detection", True):
        cmd.append("-sV")

    # OS detection needs raw sockets; without them nmap aborts the whole run.
    if config.get("os_detection", False):
        configured_privileged = get_settings().NMAP_PRIVILEGED
        is_root = _is_root()
        if configured_privileged or is_root:
            cmd.append("-O")
            if configured_privileged and not is_root:
                # Capabilities (CAP_NET_RAW) instead of root:
                # nmap must be told it may use raw sockets.
                cmd.append("--privileged")
        elif warnings is not None:
            warnings.append(OS_DETECTION_SKIPPED_WARNING)

    # NSE scripts: one vetted boolean expression, kept as a single argument.
    expression = build_script_expression(config.get("scripts", []), bool(config.get("intrusive")))
    if expression:
        cmd.append(f"--script={expression}")
        cmd.append(f"--script-timeout={NSE_SCRIPT_TIMEOUT}")

    host_timeout = config.get("host_timeout_minutes")
    if (
        isinstance(host_timeout, int)
        and not isinstance(host_timeout, bool)
        and 1 <= host_timeout <= 240
    ):
        cmd.append(f"--host-timeout={host_timeout}m")

    # Add normalized targets
    cmd.extend(normalized_targets)
    return cmd
