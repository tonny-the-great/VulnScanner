"""Nuclei scanner adapter implementation."""

from __future__ import annotations

import shutil
from typing import Any

from app.scanning.adapters.base import RawScannerResult, ScannerAdapter
from app.scanning.adapters.nuclei.command_builder import build_nuclei_command
from app.scanning.adapters.nuclei.parser import parse_nuclei_jsonl


class NucleiAdapter(ScannerAdapter):
    """Adapter for executing ProjectDiscovery Nuclei and parsing its JSONL output."""

    @property
    def name(self) -> str:
        return "nuclei"

    def is_available(self) -> bool:
        return shutil.which("nuclei") is not None

    def build_command(
        self,
        targets: list[str],
        profile_config: dict[str, Any],
        output_file_base: str,
    ) -> list[str]:
        # A missing is_intrusive key means the strictest template policy.
        nuclei_config = {
            **profile_config.get("nuclei", {}),
            "intrusive": bool(profile_config.get("is_intrusive")),
        }
        jsonl_path = f"{output_file_base}.jsonl"
        return build_nuclei_command(targets, nuclei_config, jsonl_path)

    def parse_output(
        self,
        output_file_base: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        execution_time: float,
    ) -> RawScannerResult:
        jsonl_path = f"{output_file_base}.jsonl"
        return parse_nuclei_jsonl(jsonl_path, exit_code, stdout, stderr, execution_time)
