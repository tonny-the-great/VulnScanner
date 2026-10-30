"""Fixed-window rate limiting (in-process fallback; Redis is stubbed out)."""

import uuid

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core import rate_limit
from app.core.exceptions import RateLimitExceededError


@pytest.fixture(autouse=True)
def local_store(monkeypatch):
    monkeypatch.setattr(rate_limit, "get_redis_safe", lambda: None)
    rate_limit.reset_rate_limits()
    yield
    rate_limit.reset_rate_limits()


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_ENABLED", True)


def bucket():
    return f"test-{uuid.uuid4().hex}"


@pytest.mark.parametrize(("spec", "expected"), [
    ("10/minute", (10, 60)),
    ("5/minutes", (5, 60)),
    ("1/second", (1, 1)),
    ("30/Hour", (30, 3600)),
    (" 2/days ", (2, 86400)),
])
def test_parse_rate(spec, expected):
    assert rate_limit.parse_rate(spec) == expected


@pytest.mark.parametrize("spec", ["10", "ten/minute", "10/week", "0/minute", "-1/minute", ""])
def test_parse_rate_rejects_invalid_specs(spec):
    with pytest.raises(ValueError):
        rate_limit.parse_rate(spec)


def test_eleventh_hit_in_window_is_blocked():
    name = bucket()
    now = 1_000_040.0  # 20 s into a one-minute window (windows start at multiples of 60)
    for _ in range(10):
        assert rate_limit.hit(name, "203.0.113.9", "10/minute", now=now)[0] is True
    allowed, retry_after = rate_limit.hit(name, "203.0.113.9", "10/minute", now=now)
    assert allowed is False
    assert 0 < retry_after <= 60
    assert retry_after == 40
    # Other identifiers and buckets have their own counters.
    assert rate_limit.hit(name, "203.0.113.10", "10/minute", now=now)[0] is True
    assert rate_limit.hit(bucket(), "203.0.113.9", "10/minute", now=now)[0] is True


def test_new_window_resets_the_count():
    name = bucket()
    now = 1_000_020.0
    for _ in range(3):
        rate_limit.hit(name, "user-1", "3/minute", now=now)
    assert rate_limit.hit(name, "user-1", "3/minute", now=now)[0] is False
    assert rate_limit.hit(name, "user-1", "3/minute", now=now + 60)[0] is True


def test_enforce_raises_with_retry_after(enabled):
    name = bucket()
    rate_limit.enforce_rate_limit(name, "198.51.100.1", "1/hour")
    with pytest.raises(RateLimitExceededError) as excinfo:
        rate_limit.enforce_rate_limit(name, "198.51.100.1", "1/hour")
    assert excinfo.value.status_code == 429
    assert excinfo.value.retry_after >= 1
    assert excinfo.value.headers == {"Retry-After": str(excinfo.value.retry_after)}


def test_disabled_rate_limiting_is_a_no_op(monkeypatch):
    monkeypatch.setattr(get_settings(), "RATE_LIMIT_ENABLED", False)
    name = bucket()
    for _ in range(5):
        rate_limit.enforce_rate_limit(name, "198.51.100.1", "1/hour")


def test_missing_identifier_is_not_limited(enabled):
    name = bucket()
    for _ in range(3):
        rate_limit.enforce_rate_limit(name, "", "1/hour")
        rate_limit.enforce_rate_limit(name, None, "1/hour")


def test_reset_clears_in_process_counters(enabled):
    name = bucket()
    rate_limit.enforce_rate_limit(name, "198.51.100.1", "1/hour")
    rate_limit.reset_rate_limits()
    rate_limit.enforce_rate_limit(name, "198.51.100.1", "1/hour")


def test_redis_errors_fall_back_to_local_counters(monkeypatch, enabled):
    class BrokenRedis:
        def incr(self, key):
            raise ConnectionError("down")

    failures = []
    monkeypatch.setattr(rate_limit, "get_redis_safe", lambda: BrokenRedis())
    monkeypatch.setattr(rate_limit, "mark_redis_failed", lambda: failures.append(True))
    name = bucket()
    rate_limit.enforce_rate_limit(name, "198.51.100.1", "1/hour")
    with pytest.raises(RateLimitExceededError):
        rate_limit.enforce_rate_limit(name, "198.51.100.1", "1/hour")
    assert failures


def test_dependency_factories_validate_setting_names():
    with pytest.raises(ValueError):
        rate_limit.rate_limit_by_ip("login", "NO_SUCH_RATE_LIMIT")
    with pytest.raises(ValueError):
        rate_limit.rate_limit_by_user("llm", "NO_SUCH_RATE_LIMIT")


def test_ip_dependency_returns_429_with_retry_after(monkeypatch, enabled):
    from app.main import create_app

    monkeypatch.setattr(get_settings(), "LOGIN_RATE_LIMIT", "2/minute")
    app = create_app()
    probe = APIRouter()

    @probe.get(
        "/rate-limit-probe",
        dependencies=[Depends(rate_limit.rate_limit_by_ip(bucket(), "LOGIN_RATE_LIMIT"))],
    )
    def rate_limited_probe():
        return {"ok": True}

    # Routes match in order and the console is mounted at "/", so the probe goes first.
    app.router.routes.insert(0, probe.routes[0])
    client = TestClient(app)
    assert client.get("/rate-limit-probe").status_code == 200
    assert client.get("/rate-limit-probe").status_code == 200
    blocked = client.get("/rate-limit-probe")
    assert blocked.status_code == 429
    assert blocked.json()["error_type"] == "rate_limited"
    assert int(blocked.headers["retry-after"]) >= 1
