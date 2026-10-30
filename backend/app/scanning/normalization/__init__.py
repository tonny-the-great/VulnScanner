"""Normalization package exports."""

from app.scanning.normalization.asset_normalizer import AssetNormalizer
from app.scanning.normalization.deduplicator import FindingDeduplicator
from app.scanning.normalization.finding_normalizer import normalize_raw_finding
from app.scanning.normalization.fingerprint import compute_finding_fingerprint

__all__ = [
    "AssetNormalizer",
    "FindingDeduplicator",
    "normalize_raw_finding",
    "compute_finding_fingerprint",
]
