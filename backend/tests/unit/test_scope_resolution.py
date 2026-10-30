"""Blocked networks, IPv4-in-IPv6 forms, localhost names and DNS checks in the scope gate."""

import socket
import threading
import uuid

import pytest

from app.config import get_settings
from app.core.exceptions import ScopeViolationError
from app.models.authorization import AuthorizedTarget, TargetType
from app.scanning import scope_gate
from app.scanning.scope_gate import check_resolved_targets, is_target_in_scope
from app.scanning.target_validator import validate_and_normalize_target


def _target(target_type, value):
    return AuthorizedTarget(authorization_id=uuid.uuid4(), target_type=target_type, value=value)


def _allowed(raw: str, authorized: str | None = None) -> bool:
    """Validate raw like the API does, authorize it (or `authorized`), and check scope."""
    t_type, value = validate_and_normalize_target(raw)
    a_type, a_value = validate_and_normalize_target(authorized or raw)
    return is_target_in_scope(value, t_type, [_target(a_type, a_value)])


@pytest.mark.parametrize("value", [
    "::ffff:169.254.169.254",
    "::ffff:a9fe:a9fe",
    "2002:a9fe:a9fe::1",  # 6to4 for 169.254.169.254
    "64:ff9b::a9fe:a9fe",  # NAT64 for 169.254.169.254
    "::ffff:127.0.0.1",
])
def test_ipv4_embedded_in_ipv6_is_checked_as_ipv4(value):
    assert _allowed(value) is False


def test_url_with_embedded_ipv4_host_is_refused():
    url = "http://[::ffff:a9fe:a9fe]/latest/meta-data"
    assert is_target_in_scope(url, TargetType.URL, [_target(TargetType.URL, url)]) is False


def test_local_use_nat64_addresses_are_refused():
    # RFC 8215: the embedded IPv4 position depends on the prefix length, so any address is refused.
    assert _allowed("64:ff9b:1::a9fe:a9fe") is False
    assert _allowed("64:ff9b:1:c000:2::") is False


@pytest.mark.parametrize(
    "value", ["::ffff:0:0/112", "64:ff9b::/120", "2002:a9fe::/48", "64:ff9b:1::/64"]
)
def test_ipv6_ranges_over_translation_prefixes_are_refused(value):
    # A range can reach any embedded IPv4 host, so it is refused whatever it contains.
    assert _allowed(value) is False


def test_ordinary_ipv4_inside_ipv6_forms_remain_allowed():
    assert _allowed("::ffff:192.0.2.10") is True
    assert _allowed("64:ff9b::c000:20a") is True
    assert _allowed("2001:db8::/64", "2001:db8::/48") is True


@pytest.mark.parametrize("value", ["127.0.0.1", "localhost", "app.localhost", "http://localhost:8080"])
def test_loopback_and_localhost_blocked_by_default(value):
    assert _allowed(value) is False


@pytest.mark.parametrize("value", ["127.0.0.1", "localhost", "app.localhost"])
def test_loopback_allowed_when_operator_clears_blocked_networks(monkeypatch, value):
    monkeypatch.setattr(get_settings(), "SCAN_BLOCKED_NETWORKS", "")
    assert _allowed(value) is True
    # The built-in metadata ranges stay blocked regardless of the setting.
    assert _allowed("169.254.169.254") is False


def test_operator_added_network_is_blocked(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr(
        settings, "SCAN_BLOCKED_NETWORKS", settings.SCAN_BLOCKED_NETWORKS + " 10.0.0.0/8"
    )
    assert _allowed("10.1.2.3", "10.1.0.0/16") is False
    assert _allowed("::ffff:10.1.2.3") is False
    assert _allowed("10.1.2.0/24", "10.1.0.0/16") is False
    assert _allowed("192.168.1.10") is True


@pytest.fixture
def fake_dns(monkeypatch):
    """Map hostnames to addresses (or exceptions); other names use the real resolver."""
    answers: dict[str, object] = {}
    calls: list[str] = []
    real = socket.getaddrinfo

    def getaddrinfo(host, port, *args, **kwargs):
        if host not in answers:
            return real(host, port, *args, **kwargs)
        calls.append(host)
        answer = answers[host]
        if callable(answer):
            answer = answer()
        if isinstance(answer, BaseException):
            raise answer
        infos = []
        for address in answer:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            sockaddr = (address, 0, 0, 0) if family == socket.AF_INET6 else (address, 0)
            infos.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return infos

    monkeypatch.setattr("app.scanning.scope_gate.socket.getaddrinfo", getaddrinfo)
    return answers, calls


def test_hostname_resolving_to_metadata_is_rejected(fake_dns):
    answers, _ = fake_dns
    answers["rebind.example.com"] = ["192.0.2.10", "169.254.169.254"]
    with pytest.raises(ScopeViolationError) as exc:
        check_resolved_targets([(TargetType.DOMAIN, "rebind.example.com")])
    assert (
        exc.value.detail
        == "Target rebind.example.com resolves to a blocked address (169.254.169.254)"
    )


def test_hostname_resolving_to_embedded_ipv4_is_rejected(fake_dns):
    answers, _ = fake_dns
    answers["mapped.example.com"] = ["::ffff:169.254.169.254"]
    with pytest.raises(ScopeViolationError, match="blocked address"):
        check_resolved_targets([(TargetType.URL, "https://mapped.example.com/login")])


def test_hostname_resolving_to_public_address_passes(fake_dns):
    answers, calls = fake_dns
    answers["www.example.com"] = ["192.0.2.10", "2001:db8::10"]
    answers["intranet"] = ["192.0.2.11"]
    check_resolved_targets([
        (TargetType.DOMAIN, "www.example.com"),
        (TargetType.URL, "https://www.example.com:8443/app"),
        (TargetType.HOSTNAME, "intranet"),
    ])
    assert sorted(calls) == ["intranet", "www.example.com"]  # each name is resolved once


def test_ip_and_cidr_targets_are_not_resolved(monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("IP targets must not be resolved")

    monkeypatch.setattr("app.scanning.scope_gate.socket.getaddrinfo", fail)
    check_resolved_targets([
        (TargetType.IPV4, "192.0.2.10"),
        (TargetType.IPV4_CIDR, "192.0.2.0/24"),
        (TargetType.IPV6, "2001:0db8:0000:0000:0000:0000:0000:0010"),
        (TargetType.IPV6_CIDR, "2001:db8::/64"),
        (TargetType.URL, "https://192.0.2.10:8443"),
        (TargetType.URL, "http://[2001:db8::10]/"),
    ])


def test_unresolvable_hostname_fails_closed(fake_dns):
    answers, _ = fake_dns
    answers["missing.example.com"] = socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    with pytest.raises(ScopeViolationError) as exc:
        check_resolved_targets([(TargetType.DOMAIN, "missing.example.com")])
    assert (
        exc.value.detail
        == "Target missing.example.com could not be resolved to verify that it is allowed"
    )


def test_slow_resolver_fails_closed(fake_dns, monkeypatch):
    answers, _ = fake_dns
    release = threading.Event()

    def slow():
        release.wait(5)
        return ["192.0.2.10"]

    answers["slow.example.com"] = slow
    monkeypatch.setattr(get_settings(), "SCAN_DNS_TIMEOUT_SECONDS", 0.2)
    try:
        with pytest.raises(ScopeViolationError, match="could not be resolved"):
            check_resolved_targets([(TargetType.DOMAIN, "slow.example.com")])
    finally:
        release.set()


def test_blocked_networks_combine_builtin_and_settings(monkeypatch):
    monkeypatch.setattr(get_settings(), "SCAN_BLOCKED_NETWORKS", "10.0.0.0/8")
    networks = {str(n) for n in scope_gate.blocked_networks()}
    assert {"169.254.0.0/16", "fe80::/10", "10.0.0.0/8"} <= networks
    assert "127.0.0.0/8" not in networks
