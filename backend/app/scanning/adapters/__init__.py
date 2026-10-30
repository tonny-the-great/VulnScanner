"""Scanner adapters registry."""

from app.scanning.adapters.base import (
    RawDiscoveredAsset,
    RawDiscoveredService,
    RawFinding,
    RawFindingEvidence,
    RawScannerResult,
    ScannerAdapter,
)
from app.scanning.adapters.nmap import NmapAdapter
from app.scanning.adapters.nuclei import NucleiAdapter
from app.scanning.adapters.testssl import TestSSLAdapter

ADAPTER_REGISTRY: dict[str, ScannerAdapter] = {
    "nmap": NmapAdapter(),
    "nuclei": NucleiAdapter(),
    "testssl": TestSSLAdapter(),
}

__all__ = [
    "ScannerAdapter",
    "RawDiscoveredAsset",
    "RawDiscoveredService",
    "RawFinding",
    "RawFindingEvidence",
    "RawScannerResult",
    "NmapAdapter",
    "NucleiAdapter",
    "TestSSLAdapter",
    "ADAPTER_REGISTRY",
]
