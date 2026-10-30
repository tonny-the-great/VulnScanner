"""testssl.sh scanner adapter implementation."""

from __future__ import annotations

import shutil
from typing import Any

from app.scanning.adapters.base import RawScannerResult, ScannerAdapter
from app.scanning.adapters.testssl.command_builder import build_testssl_command
from app.scanning.adapters.testssl.parser import parse_testssl_json


class TestSSLAdapter(ScannerAdapter):
    """Adapter for executing testssl.sh and parsing its JSON output."""

    @property
    def name(self) -> str:
        return "testssl"

    def is_available(self) -> bool:
        return shutil.which("testssl.sh") is not None or shutil.which("testssl") is not None

    def build_command(
        self,
        targets: list[str],
        profile_config: dict[str, Any],
        output_file_base: str,
    ) -> list[str]:
        testssl_config = profile_config.get("testssl", {})
        json_path = f"{output_file_base}.json"
        return build_testssl_command(targets, testssl_config, json_path)

    def parse_output(
        self,
        output_file_base: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        execution_time: float,
    ) -> RawScannerResult:
        json_path = f"{output_file_base}.json"
        return parse_testssl_json(json_path, exit_code, stdout, stderr, execution_time)
