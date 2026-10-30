"""Unit tests for target validation and normalization."""

import pytest

from app.core.exceptions import ValidationError
from app.models.authorization import TargetType
from app.scanning.target_validator import validate_and_normalize_target


def test_valid_ipv4():
    t_type, norm = validate_and_normalize_target("192.168.1.100")
    assert t_type == TargetType.IPV4
    assert norm == "192.168.1.100"


def test_valid_ipv4_cidr():
    t_type, norm = validate_and_normalize_target("10.0.0.0/24")
    assert t_type == TargetType.IPV4_CIDR
    assert norm == "10.0.0.0/24"


def test_broad_cidr_rejected():
    with pytest.raises(ValidationError, match="too broad"):
        validate_and_normalize_target("10.0.0.0/8")


def test_valid_hostname():
    t_type, norm = validate_and_normalize_target("app.example.com")
    assert t_type == TargetType.DOMAIN
    assert norm == "app.example.com"


def test_valid_url():
    t_type, norm = validate_and_normalize_target("https://secure.example.com:8443/login")
    assert t_type == TargetType.URL
    assert norm == "https://secure.example.com:8443/login"


def test_shell_injection_characters_rejected():
    dangerous_inputs = [
        "192.168.1.1; cat /etc/passwd",
        "example.com | rm -rf /",
        "192.168.1.1 `id`",
        "$(whoami).example.com",
        "example.com & ping 127.0.0.1",
        "example.com > out.txt",
        "example.com\n127.0.0.1",
        "example.com' OR '1'='1",
        "example.com\"",
    ]
    for inp in dangerous_inputs:
        with pytest.raises(ValidationError):
            validate_and_normalize_target(inp)
