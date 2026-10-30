"""Client IP resolution must not trust client-supplied forwarding headers."""

import asyncio

import pytest

from app.config import get_settings
from app.core.request_context import (
    RequestContextMiddleware,
    client_ip_from_scope,
    current_request_context,
)


def scope(peer="10.0.0.2", forwarded=(), user_agent=None):
    headers = [(b"x-forwarded-for", value.encode("latin-1")) for value in forwarded]
    if user_agent is not None:
        headers.append((b"user-agent", user_agent.encode("latin-1")))
    return {"type": "http", "client": (peer, 51234) if peer else None, "headers": headers}


@pytest.fixture
def hops(monkeypatch):
    def set_hops(value):
        monkeypatch.setattr(get_settings(), "TRUSTED_PROXY_HOPS", value)
    return set_hops


def test_without_trusted_proxies_forwarded_header_is_ignored(hops):
    hops(0)
    assert client_ip_from_scope(scope(forwarded=["203.0.113.7"])) == "10.0.0.2"


def test_one_trusted_proxy_uses_the_address_it_saw(hops):
    hops(1)
    assert client_ip_from_scope(scope(forwarded=["198.51.100.20"])) == "198.51.100.20"
    # A client-supplied entry to the left of the proxy's own is ignored.
    assert client_ip_from_scope(scope(forwarded=["1.2.3.4, 198.51.100.20"])) == "198.51.100.20"
    # Repeated headers are read in order, as if joined.
    assert client_ip_from_scope(scope(forwarded=["1.2.3.4", "198.51.100.20"])) == "198.51.100.20"


def test_missing_forwarded_header_falls_back_to_peer(hops):
    hops(1)
    assert client_ip_from_scope(scope()) == "10.0.0.2"
    hops(2)
    # Only one proxy hop present although two are configured.
    assert client_ip_from_scope(scope(forwarded=["198.51.100.20"])) == "10.0.0.2"


@pytest.mark.parametrize(
    "value", ["garbage", "999.1.1.1", "1" * 200, "<script>", "198.51.100.20:8080"]
)
def test_invalid_forwarded_values_fall_back_to_peer(hops, value):
    hops(1)
    assert client_ip_from_scope(scope(forwarded=[value])) == "10.0.0.2"


def test_ipv6_entries_are_unbracketed_and_normalized(hops):
    hops(1)
    assert client_ip_from_scope(scope(forwarded=["[2001:DB8::1]"])) == "2001:db8::1"
    assert client_ip_from_scope(scope(forwarded=["2001:db8:0:0::7"])) == "2001:db8::7"


def test_two_hops_behind_external_https_proxy(hops):
    hops(2)
    # client -> external HTTPS proxy -> nginx -> API: nginx appended the external
    # proxy's address, which in turn recorded the client's.
    chain = ["6.6.6.6, 203.0.113.50, 172.18.0.1"]
    assert client_ip_from_scope(scope(peer="172.18.0.5", forwarded=chain)) == "203.0.113.50"


def test_peer_without_address_and_test_client_peer(hops):
    hops(1)
    assert client_ip_from_scope(scope(peer=None, forwarded=["198.51.100.20"])) is None
    hops(0)
    assert client_ip_from_scope(scope(peer="testclient")) == "testclient"


def test_middleware_publishes_and_resets_context(hops):
    hops(0)
    seen = []

    async def app(scope, receive, send):
        seen.append(current_request_context())

    middleware = RequestContextMiddleware(app)
    asyncio.run(middleware(scope(user_agent="agent/" + "x" * 600), None, None))
    assert seen[0].ip_address == "10.0.0.2"
    assert seen[0].user_agent.startswith("agent/") and len(seen[0].user_agent) == 512
    assert current_request_context() is None

    asyncio.run(middleware({"type": "lifespan"}, None, None))
    assert seen[1] is None
