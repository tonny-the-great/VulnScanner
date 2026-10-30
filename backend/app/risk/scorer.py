"""
Documented risk and priority scoring engine.

Calculates an organization-level Priority Score (0.0 – 10.0).
This score is clearly documented and labeled as:
'Application Priority Score — not CVSS'
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime

from app.models.finding import FindingConfidence, FindingSeverity

DEFAULT_SEVERITY_SCORES: dict[FindingSeverity, float] = {
    FindingSeverity.CRITICAL: 9.0,
    FindingSeverity.HIGH: 7.0,
    FindingSeverity.MEDIUM: 5.0,
    FindingSeverity.LOW: 2.0,
    FindingSeverity.INFO: 0.5,
}

CONFIDENCE_FACTORS: dict[FindingConfidence, float] = {
    FindingConfidence.CONFIRMED: 1.0,
    FindingConfidence.LIKELY: 0.85,
    FindingConfidence.UNVERIFIED: 0.60,
}


def is_public_ip(ip_str: str | None) -> bool:
    """Return True if ip_str is a routable global public IP."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_global and not ip.is_private and not ip.is_loopback and not ip.is_reserved
    except ValueError:
        return False


def calculate_priority_score(
    severity: FindingSeverity,
    confidence: FindingConfidence,
    cvss_score: float | None = None,
    target_ip: str | None = None,
    scan_recurrence_count: int = 1,
    first_seen: datetime | None = None,
) -> float:
    """
    Compute overall 0.0 - 10.0 Priority Score based on documented factors.

    Factors:
      1. Base score: CVSS when given (0-10), else a per-severity default.
      2. Confidence factor: CONFIRMED 1.0, LIKELY 0.85, UNVERIFIED 0.60.
      3. Exposure factor: 1.15 for a public (globally routable) target IP.
      4. Recurrence bonus: +0.3 when seen in more than two distinct scans
         (scan_recurrence_count counts scans including the current one).
      5. Age factor: +0.2 when open more than 30 days, +0.4 beyond 90 days,
         measured from first_seen (a naive datetime is taken to be UTC).

    The result is clamped to 0.0 - 10.0 and rounded to two decimals.
    """
    # 1. Base Score
    if cvss_score is not None and 0.0 <= cvss_score <= 10.0:
        base_score = float(cvss_score)
    else:
        base_score = DEFAULT_SEVERITY_SCORES.get(severity, 5.0)

    # 2. Confidence Factor
    confidence_factor = CONFIDENCE_FACTORS.get(confidence, 0.85)

    # 3. Exposure Factor (Public internet facing = 1.15 multiplier, capped)
    exposure_factor = 1.15 if is_public_ip(target_ip) else 1.0

    # 4. Recurrence bonus
    recurrence_bonus = 0.3 if scan_recurrence_count > 2 else 0.0

    # 5. Age factor
    age_factor = 0.0
    if first_seen:
        if first_seen.tzinfo is None or first_seen.utcoffset() is None:
            # Naive values (e.g. from SQLite) are stored as UTC.
            first_seen = first_seen.replace(tzinfo=UTC)
        now = datetime.now(UTC)
        days_open = (now - first_seen).total_seconds() / 86400.0
        if days_open > 90:
            age_factor = 0.4
        elif days_open > 30:
            age_factor = 0.2

    # Final calculation
    raw_score = (base_score * confidence_factor * exposure_factor) + recurrence_bonus + age_factor
    score = round(max(0.0, min(10.0, raw_score)), 2)
    return score
