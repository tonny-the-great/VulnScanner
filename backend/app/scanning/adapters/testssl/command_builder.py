"""testssl.sh command builder."""

from __future__ import annotations

import shutil
from typing import Any
from urllib.parse import urlparse

from app.core.exceptions import ValidationError
from app.models.authorization import TargetType
from app.scanning.target_validator import validate_and_normalize_target


def build_testssl_command(
    targets: list[str],
    config: dict[str, Any],
    output_json_path: str,
) -> list[str]:
    """Construct command arguments for testssl.sh execution."""
    if not targets:
        raise ValidationError("No targets provided for testssl scan")

    # The orchestrator runs testssl once per target; never silently drop the rest.
    if len(targets) > 1:
        raise ValidationError("testssl.sh scans one target per run")
    target_type, norm = validate_and_normalize_target(targets[0])
    if target_type in (TargetType.IPV4_CIDR, TargetType.IPV6_CIDR):
        raise ValidationError("testssl.sh cannot scan address ranges")

    # Format host:port if URL or plain host
    if norm.startswith(("http://", "https://")):
        parsed = urlparse(norm)
        host = parsed.hostname or norm
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target_spec = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    else:
        target_spec = norm

    # Distribution packages install the script as "testssl"; upstream names it "testssl.sh".
    executable = shutil.which("testssl.sh") or shutil.which("testssl") or "testssl.sh"
    cmd = [
        executable,
        # Flat JSON array of findings; --jsonfile-pretty nests results under "scanResult".
        "--jsonfile", output_json_path,
        "--warnings", "off",
        "--color", "0",
    ]

    checks = config.get("checks", [])
    if "protocols" in checks:
        cmd.append("-p")
    if "ciphers" in checks:
        cmd.append("-e")
    if "vulnerabilities" in checks:
        cmd.append("-U")

    cmd.append(target_spec)
    return cmd
