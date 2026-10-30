"""Nmap scanner adapter implementation."""

from __future__ import annotations

import json
import logging
import shutil
from pathlib import Path
from typing import Any

from app.scanning.adapters.base import RawScannerResult, ScannerAdapter
from app.scanning.adapters.nmap.command_builder import build_nmap_command
from app.scanning.adapters.nmap.parser import parse_nmap_xml

logger = logging.getLogger(__name__)


def _warnings_path(output_file_base: str) -> Path:
    return Path(f"{output_file_base}.warnings.json")


class NmapAdapter(ScannerAdapter):
    """
    Adapter for executing Nmap and parsing its XML output.

    Warnings raised while building the command (e.g. a skipped option) are kept in a
    sidecar file next to the output, so the adapter stays stateless and thread-safe.
    """

    @property
    def name(self) -> str:
        return "nmap"

    def is_available(self) -> bool:
        return shutil.which("nmap") is not None

    def build_command(
        self,
        targets: list[str],
        profile_config: dict[str, Any],
        output_file_base: str,
    ) -> list[str]:
        # A missing is_intrusive key means the strictest script policy.
        nmap_config = {
            **profile_config.get("nmap", {}),
            "intrusive": bool(profile_config.get("is_intrusive")),
        }
        xml_path = f"{output_file_base}.xml"
        warnings: list[str] = []
        command = build_nmap_command(targets, nmap_config, xml_path, warnings)
        sidecar = _warnings_path(output_file_base)
        try:
            if warnings:
                sidecar.write_text(json.dumps(warnings), encoding="utf-8")
            else:
                sidecar.unlink(missing_ok=True)
        except OSError as e:
            logger.warning("Could not update nmap warnings file %s: %s", sidecar, e)
        return command

    def parse_output(
        self,
        output_file_base: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        execution_time: float,
    ) -> RawScannerResult:
        xml_path = f"{output_file_base}.xml"
        result = parse_nmap_xml(xml_path, exit_code, stdout, stderr, execution_time)
        build_warnings: list[str] = []
        try:
            loaded = json.loads(_warnings_path(output_file_base).read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                build_warnings = [str(w) for w in loaded]
        except (OSError, ValueError):
            pass
        result.warnings = build_warnings + result.warnings
        return result
