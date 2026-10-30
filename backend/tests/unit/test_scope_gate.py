"""Unit tests for scope verification."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from app.core.exceptions import ScopeViolationError
from app.models.authorization import AuthorizedTarget, ScopeAuthorization, TargetType
from app.scanning.scope_gate import is_target_in_scope, verify_scan_scope


def test_ip_in_cidr_scope():
    auth_target = AuthorizedTarget(
        authorization_id=uuid.uuid4(),
        target_type=TargetType.IPV4_CIDR,
        value="192.168.1.0/24",
    )
    assert is_target_in_scope("192.168.1.50", TargetType.IPV4, [auth_target]) is True
    assert is_target_in_scope("192.168.2.50", TargetType.IPV4, [auth_target]) is False


def test_subdomain_scope():
    auth_target = AuthorizedTarget(
        authorization_id=uuid.uuid4(),
        target_type=TargetType.DOMAIN,
        value="example.com",
    )
    assert is_target_in_scope("api.example.com", TargetType.DOMAIN, [auth_target]) is True
    assert is_target_in_scope("otherdomain.com", TargetType.DOMAIN, [auth_target]) is False


def test_disallowed_cloud_metadata():
    auth_target = AuthorizedTarget(
        authorization_id=uuid.uuid4(),
        target_type=TargetType.IPV4,
        value="169.254.169.254",
    )
    assert is_target_in_scope("169.254.169.254", TargetType.IPV4, [auth_target]) is False


def test_verify_scan_scope_expired_raises():
    today = datetime.now(UTC).date()
    auth = ScopeAuthorization(
        organization_id=uuid.uuid4(),
        title="Expired Auth",
        signer_name="Test",
        signer_email="test@example.com",
        # The model compares against the UTC date; a local date.today() is a day
        # ahead of it for part of the day in timezones east of UTC.
        authorization_date=today - timedelta(days=40),
        expiration_date=today - timedelta(days=1),
        created_by=uuid.uuid4(),
    )
    with pytest.raises(ScopeViolationError, match="expired"):
        verify_scan_scope(auth, [(TargetType.IPV4, "192.168.1.1")])


def _target(target_type, value):
    return AuthorizedTarget(authorization_id=uuid.uuid4(), target_type=target_type, value=value)


@pytest.mark.parametrize("value,target_type", [
    ("http://169.254.169.254/latest/meta-data", TargetType.URL),
    ("169.254.169.0/24", TargetType.IPV4_CIDR),
    ("2852039166", TargetType.HOSTNAME),
    ("0xa9fea9fe", TargetType.HOSTNAME),
    ("metadata.google.internal", TargetType.DOMAIN),
])
def test_metadata_blocklist_cannot_be_bypassed(value, target_type):
    authorized = [_target(target_type, value), _target(TargetType.IPV4_CIDR, "169.254.0.0/16")]
    assert is_target_in_scope(value, target_type, authorized) is False


def test_ipv6_scope_matching():
    authorized = [_target(TargetType.IPV6_CIDR, "2001:db8::/48")]
    assert is_target_in_scope("2001:db8::/64", TargetType.IPV6_CIDR, authorized) is True
    exploded = "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert (
        is_target_in_scope(exploded, TargetType.IPV6, [_target(TargetType.IPV6, "2001:db8::1")])
        is True
    )
    assert is_target_in_scope("2001:db9::/64", TargetType.IPV6_CIDR, authorized) is False


def test_url_host_matching():
    assert (
        is_target_in_scope(
            "https://app.example.com/login",
            TargetType.URL,
            [_target(TargetType.DOMAIN, "example.com")],
        )
        is True
    )
    assert (
        is_target_in_scope(
            "http://10.0.0.5:8080", TargetType.URL, [_target(TargetType.IPV4_CIDR, "10.0.0.0/24")]
        )
        is True
    )
    assert (
        is_target_in_scope(
            "https://example.org", TargetType.URL, [_target(TargetType.DOMAIN, "example.com")]
        )
        is False
    )
