"""Unit tests for risk and priority scoring."""

from datetime import UTC, datetime, timedelta

from app.models.finding import FindingConfidence, FindingSeverity
from app.risk.scorer import calculate_priority_score, is_public_ip


def test_public_ip_detection():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("10.0.0.5") is False
    assert is_public_ip("127.0.0.1") is False


def test_priority_score_calculation():
    # Confirmed Critical on internal IP
    score = calculate_priority_score(
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CONFIRMED,
        cvss_score=9.8,
        target_ip="192.168.1.5",
    )
    assert 9.0 <= score <= 10.0


def test_priority_score_public_ip_multiplier():
    score_internal = calculate_priority_score(
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.LIKELY,
        target_ip="10.0.0.1",
    )
    score_public = calculate_priority_score(
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.LIKELY,
        target_ip="93.184.216.34",
    )
    assert score_public > score_internal


def test_priority_score_capped_at_ten():
    score = calculate_priority_score(
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CONFIRMED,
        cvss_score=10.0,
        target_ip="93.184.216.34",
        scan_recurrence_count=5,
        first_seen=datetime.now(UTC) - timedelta(days=120),
    )
    assert score == 10.0


def test_priority_score_accepts_naive_first_seen_as_utc():
    naive = (datetime.now(UTC) - timedelta(days=45)).replace(tzinfo=None)
    aware = naive.replace(tzinfo=UTC)
    kwargs = dict(
        severity=FindingSeverity.MEDIUM, confidence=FindingConfidence.CONFIRMED, cvss_score=5.0
    )
    naive_score = calculate_priority_score(**kwargs, first_seen=naive)
    assert naive_score == calculate_priority_score(**kwargs, first_seen=aware)
    # 45 days open adds the 30-day age factor.
    assert naive_score == calculate_priority_score(**kwargs) + 0.2
