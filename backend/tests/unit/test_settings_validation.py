"""Settings validation: unsafe or inconsistent configuration fails at startup."""

import ipaddress

import pytest
from pydantic import ValidationError

from app.config import Settings

SECRET = "x" * 40


def make(**overrides):
    return Settings(_env_file=None, SESSION_SECRET=SECRET, **overrides)


def test_wildcard_cors_origin_is_rejected():
    with pytest.raises(ValidationError, match="CORS_ORIGINS"):
        make(CORS_ORIGINS="https://console.example.com *")


@pytest.mark.parametrize(("email", "password"), [
    ("root@example.com", ""),
    ("", "Platform-Bootstrap-Secret-2026!"),
    ("root@example.com", "   "),
])
def test_half_configured_bootstrap_superuser_is_rejected(email, password):
    with pytest.raises(ValidationError, match="FIRST_SUPERUSER"):
        make(FIRST_SUPERUSER_EMAIL=email, FIRST_SUPERUSER_PASSWORD=password)


def test_bootstrap_superuser_may_be_fully_set_or_unset():
    make(FIRST_SUPERUSER_EMAIL="", FIRST_SUPERUSER_PASSWORD="")
    make(
        FIRST_SUPERUSER_EMAIL="root@example.com",
        FIRST_SUPERUSER_PASSWORD="Platform-Bootstrap-Secret-2026!",
    )


@pytest.mark.parametrize(
    "value", ["ten/minute", "10 per minute", "10/fortnight", "0/minute", "10/", "/minute"]
)
def test_malformed_rate_limits_are_rejected(value):
    with pytest.raises(ValidationError, match="Rate limits"):
        make(LOGIN_RATE_LIMIT=value)
    with pytest.raises(ValidationError, match="Rate limits"):
        make(REPORT_DOWNLOAD_RATE_LIMIT=value)


@pytest.mark.parametrize("value", ["10/minute", "5/Hours", "1/second", " 100/DAY "])
def test_valid_rate_limits_are_accepted(value):
    assert make(REGISTER_RATE_LIMIT=value).REGISTER_RATE_LIMIT == value.strip()


@pytest.mark.parametrize("value", ["10.0.0.0/33", "not-a-network", "127.0.0.0/8, example.com"])
def test_invalid_blocked_networks_are_rejected(value):
    with pytest.raises(ValidationError, match="SCAN_BLOCKED_NETWORKS"):
        make(SCAN_BLOCKED_NETWORKS=value)


def test_blocked_networks_parse_commas_and_whitespace():
    settings = make(SCAN_BLOCKED_NETWORKS="127.0.0.0/8, 10.0.0.1\n172.18.0.0/16 ::1/128")
    assert settings.scan_blocked_networks == (
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.1/32"),
        ipaddress.ip_network("172.18.0.0/16"),
        ipaddress.ip_network("::1/128"),
    )
    assert make(SCAN_BLOCKED_NETWORKS="").scan_blocked_networks == ()
    defaults = make().scan_blocked_networks
    assert ipaddress.ip_network("127.0.0.0/8") in defaults
    assert ipaddress.ip_network("::1/128") in defaults


def test_numeric_bounds_are_enforced():
    with pytest.raises(ValidationError):
        make(SCAN_TIMEOUT=10)
    with pytest.raises(ValidationError):
        make(MAX_TARGETS_PER_SCAN=0)
    with pytest.raises(ValidationError):
        make(ACCESS_TOKEN_EXPIRE_MINUTES=0)
    with pytest.raises(ValidationError):
        make(TRUSTED_PROXY_HOPS=6)


def test_log_level_is_normalized_and_checked():
    assert make(LOG_LEVEL="debug").LOG_LEVEL == "DEBUG"
    with pytest.raises(ValidationError, match="LOG_LEVEL"):
        make(LOG_LEVEL="verbose")


def test_environment_defaults_to_production(monkeypatch):
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    settings = make()
    assert settings.ENVIRONMENT == "production"
    assert settings.is_production
    assert not settings.is_development and not settings.is_testing
    assert settings.api_docs_enabled is False


def test_api_docs_follow_environment_unless_overridden():
    assert make(ENVIRONMENT="development").api_docs_enabled is True
    assert make(ENVIRONMENT="testing").api_docs_enabled is True
    assert make(ENVIRONMENT="production", ENABLE_API_DOCS=True).api_docs_enabled is True
    assert make(ENVIRONMENT="development", ENABLE_API_DOCS=False).api_docs_enabled is False


def test_empty_environment_values_count_as_unset(monkeypatch):
    monkeypatch.setenv("ENABLE_API_DOCS", "")
    monkeypatch.setenv("LOG_LEVEL", "")
    monkeypatch.setenv("SCAN_TIMEOUT", "")
    settings = make()
    assert settings.ENABLE_API_DOCS is None
    assert settings.LOG_LEVEL == "INFO"
    assert settings.SCAN_TIMEOUT == 3600
