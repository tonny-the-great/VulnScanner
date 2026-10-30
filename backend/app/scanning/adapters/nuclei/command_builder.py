"""Nuclei command builder with parameter validation."""

from __future__ import annotations

import re
from typing import Any

from app.core.exceptions import ValidationError
from app.scanning.target_validator import validate_and_normalize_target


def build_nuclei_command(
    targets: list[str],
    config: dict[str, Any],
    output_jsonl_path: str,
) -> list[str]:
    """
    Construct safe command argument list for Nuclei execution.
    """
    if not targets:
        raise ValidationError("No targets provided for Nuclei scan")

    normalized_targets: list[str] = []
    for t in targets:
        _, norm = validate_and_normalize_target(t)
        normalized_targets.append(norm)

    cmd = [
        "nuclei",
        "-jsonl",
        "-o", output_jsonl_path,
        "-silent",
        "-nc",  # no colors
        # -ni disables interactsh, so no payloads or callbacks go to public OAST servers.
        "-ni",
    ]

    # Denial-of-service and fuzzing templates never run; intrusive ones only in intrusive profiles.
    excluded_tags = ["dos", "fuzz"]
    if not config.get("intrusive"):
        excluded_tags.append("intrusive")
    cmd.extend(["-etags", ",".join(excluded_tags)])

    # Target arguments
    for t in normalized_targets:
        cmd.extend(["-u", t])

    # Rate limiting (requests per second, default 150)
    rate_limit = config.get("rate_limit", 150)
    if isinstance(rate_limit, int) and 10 <= rate_limit <= 1000:
        cmd.extend(["-rl", str(rate_limit)])

    # Severity filter
    severities = config.get("severity", [])
    valid_sevs = [s for s in severities if s in ("critical", "high", "medium", "low", "info")]
    if valid_sevs:
        cmd.extend(["-s", ",".join(valid_sevs)])

    # Tags filter
    tags = config.get("tags", [])
    if tags:
        # Sanitize tags (only alphanumeric and hyphen)
        clean_tags = [
            str(tag).strip() for tag in tags if re.fullmatch(r"[A-Za-z0-9-]+", str(tag).strip())
        ]
        if clean_tags:
            cmd.extend(["-tags", ",".join(clean_tags)])

    return cmd
