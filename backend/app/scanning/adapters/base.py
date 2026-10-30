"""
Abstract base classes and contracts for scanner adapters.

CRITICAL DESIGN RULE:
Adapters must return pure data structures (RawScannerResult, RawFinding, RawDiscoveredAsset).
They do NOT interact directly with database models. The Normalization layer
is responsible for mapping raw results into DB entities.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any

from app.models.asset import AssetType, ServiceProtocol, ServiceState
from app.models.finding import FindingConfidence, FindingSeverity


@dataclass
class RawDiscoveredService:
    protocol: ServiceProtocol
    port: int
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extra_info: str | None = None
    state: ServiceState = ServiceState.OPEN


@dataclass
class RawDiscoveredAsset:
    asset_type: AssetType
    ip_address: str | None = None
    hostname: str | None = None
    domain: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_confidence: int | None = None
    services: list[RawDiscoveredService] = field(default_factory=list)


@dataclass
class RawFindingEvidence:
    evidence_type: str
    content: str


@dataclass
class RawFinding:
    title: str
    description: str | None
    source_tool: str
    scanner_reference: str | None
    confidence: FindingConfidence
    cve_ids: list[str]
    cwe_ids: list[str]
    severity: FindingSeverity
    cvss_score: float | None = None
    cvss_vector: str | None = None
    port: int | None = None
    protocol: str | None = None
    target_address: str = ""
    evidence: list[RawFindingEvidence] = field(default_factory=list)


@dataclass
class RawScannerResult:
    tool_name: str
    exit_code: int
    execution_time_seconds: float
    raw_output_path: str | None = None
    raw_text: str | None = None
    assets: list[RawDiscoveredAsset] = field(default_factory=list)
    findings: list[RawFinding] = field(default_factory=list)
    error_message: str | None = None
    # Human-readable, non-sensitive notes (e.g. a skipped option); shown as scan events.
    warnings: list[str] = field(default_factory=list)


class ScannerAdapter(abc.ABC):
    """Abstract interface that all scanner tool integrations must implement."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the scanner (e.g. 'nmap', 'nuclei', 'testssl')."""
        ...

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True if the underlying tool executable is present in PATH."""
        ...

    @abc.abstractmethod
    def build_command(
        self,
        targets: list[str],
        profile_config: dict[str, Any],
        output_file_base: str,
    ) -> list[str]:
        """
        Build an argument list suitable for subprocess execution.

        MUST return a list of strings, never a raw shell string.
        MUST validate inputs against injection attacks.
        """
        ...

    @abc.abstractmethod
    def parse_output(
        self,
        output_file_base: str,
        exit_code: int,
        stdout: str,
        stderr: str,
        execution_time: float,
    ) -> RawScannerResult:
        """
        Parse tool output files/stdout into standardized RawScannerResult.
        """
        ...
