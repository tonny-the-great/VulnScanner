"""
Scope gate — authorization and scope boundary enforcement.

CRITICAL:
No scan can execute unless every target is verified against an active,
valid ScopeAuthorization belonging to the organization.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from urllib.parse import urlparse

from app.config import get_settings
from app.core.exceptions import ScopeViolationError
from app.models.authorization import AuthorizedTarget, ScopeAuthorization, TargetType

IP_TARGET_TYPES = (TargetType.IPV4, TargetType.IPV4_CIDR, TargetType.IPV6, TargetType.IPV6_CIDR)

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Disallowed targets to prevent SSRF against cloud metadata services. Link-local
# ranges are blocked whole, whether given as an address, a CIDR, or a URL host.
# Operators extend this with SCAN_BLOCKED_NETWORKS (loopback by default).
DISALLOWED_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),  # IPv4 link-local, incl. 169.254.169.254
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 metadata endpoint
)
DISALLOWED_HOSTNAMES = {"metadata.google.internal", "metadata"}
# Hostnames like "2852039166" or "0xa9fea9fe" are resolved as IPv4 addresses by scanners.
NUMERIC_HOST_REGEX = re.compile(r"(0x[0-9a-f]+|[0-9]+)", re.IGNORECASE)

# IPv6 ranges that carry an IPv4 address; traffic to them can reach that IPv4 host.
IPV4_MAPPED_NETWORK = ipaddress.ip_network("::ffff:0:0/96")
SIXTOFOUR_NETWORK = ipaddress.ip_network("2002::/16")
NAT64_NETWORK = ipaddress.ip_network("64:ff9b::/96")
# RFC 8215 local-use NAT64 prefix. Where the IPv4 address sits depends on the
# operator's prefix length, so every address in it is refused.
NAT64_LOCAL_NETWORK = ipaddress.ip_network("64:ff9b:1::/48")
IPV4_TRANSLATION_NETWORKS = (
    IPV4_MAPPED_NETWORK,
    SIXTOFOUR_NETWORK,
    NAT64_NETWORK,
    NAT64_LOCAL_NETWORK,
)
# Not covered (rarely routed to IPv4 by current stacks): the deprecated
# IPv4-compatible form ::a.b.c.d and Teredo (2001::/32).

_LOOPBACK_V4 = ipaddress.IPv4Address("127.0.0.1")


def _as_network(value: str) -> IPNetwork | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def blocked_networks() -> tuple[IPNetwork, ...]:
    """Networks no scan may touch: the built-in list plus SCAN_BLOCKED_NETWORKS."""
    return DISALLOWED_NETWORKS + tuple(get_settings().scan_blocked_networks)


def _embedded_ipv4(address: ipaddress.IPv6Address) -> ipaddress.IPv4Address | None:
    """Return the IPv4 address an IPv4-mapped, 6to4 or NAT64 address reaches."""
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None:
        return address.sixtofour
    if address in NAT64_NETWORK:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


def _network_disallowed(net: IPNetwork, blocked: tuple[IPNetwork, ...]) -> bool:
    if any(net.version == b.version and net.overlaps(b) for b in blocked):
        return True
    if net.version != 6:
        return False
    if net.num_addresses == 1:
        if net.network_address in NAT64_LOCAL_NETWORK:
            return True
        embedded = _embedded_ipv4(net.network_address)
        return embedded is not None and any(
            b.version == 4 and embedded in b for b in blocked
        )
    # A range inside a translation prefix could reach any IPv4 host; refuse it whole.
    return any(net.overlaps(t) for t in IPV4_TRANSLATION_NETWORKS)


def _blocks_localhost(blocked: tuple[IPNetwork, ...]) -> bool:
    return any(b.version == 4 and _LOOPBACK_V4 in b for b in blocked)


def _is_disallowed(host: str, blocked: tuple[IPNetwork, ...] | None = None) -> bool:
    host = host.lower().rstrip(".")
    if host in DISALLOWED_HOSTNAMES or NUMERIC_HOST_REGEX.fullmatch(host):
        return True
    if blocked is None:
        blocked = blocked_networks()
    net = _as_network(host)
    if net is None:
        return (host == "localhost" or host.endswith(".localhost")) and _blocks_localhost(blocked)
    return _network_disallowed(net, blocked)


def is_target_in_scope(
    target_value: str, target_type: TargetType, authorized_targets: list[AuthorizedTarget]
) -> bool:
    """
    Check if a single validated target is covered by any authorized target in the list.
    """
    host = (
        (urlparse(target_value).hostname or "") if target_type == TargetType.URL else target_value
    )
    if _is_disallowed(host):
        return False
    host = host.lower()
    # Addresses and ranges compare as networks, so IPv6 spelling differences do not matter.
    target_net = _as_network(host)

    for auth in authorized_targets:
        auth_value = auth.value.lower()

        # 1. Exact string match
        if target_value.lower() == auth_value or host == auth_value:
            return True

        # 2. Address or range inside an authorized address or range (same IP family)
        auth_net = _as_network(auth_value) if auth.target_type in IP_TARGET_TYPES else None
        if (
            target_net is not None
            and auth_net is not None
            and target_net.version == auth_net.version
        ):
            if target_net.subnet_of(auth_net):
                return True

        # 3. Host or subdomain of an authorized hostname/domain (bare host or URL host)
        if target_net is None and auth.target_type in (TargetType.HOSTNAME, TargetType.DOMAIN):
            if host.endswith(f".{auth_value}"):
                return True

    return False


def verify_scan_scope(
    authorization: ScopeAuthorization,
    targets: list[tuple[TargetType, str]],
) -> None:
    """
    Verify that an authorization is valid and all targets fall strictly within its scope.

    Raises ScopeViolationError if the authorization is revoked, expired,
    has no targets, or if any target is outside the authorized boundaries.
    """
    if not authorization.is_valid:
        if authorization.is_revoked:
            raise ScopeViolationError(
                f"Scope authorization '{authorization.title}' has been revoked"
            )
        raise ScopeViolationError(
            f"Scope authorization '{authorization.title}' has expired"
        )

    auth_targets = authorization.authorized_targets
    if not auth_targets:
        raise ScopeViolationError(
            f"Scope authorization '{authorization.title}' has no authorized targets configured"
        )

    unauthorized_targets: list[str] = []
    for t_type, t_val in targets:
        if not is_target_in_scope(t_val, t_type, auth_targets):
            unauthorized_targets.append(t_val)

    if unauthorized_targets:
        raise ScopeViolationError(
            f"The following targets are not covered by the authorization scope: "
            f"{', '.join(unauthorized_targets)}"
        )


def _host_to_resolve(target_type: TargetType, target_value: str) -> str | None:
    if target_type in (TargetType.HOSTNAME, TargetType.DOMAIN):
        host = target_value
    elif target_type == TargetType.URL:
        host = urlparse(target_value).hostname or ""
        if _as_network(host) is not None:
            return None
    else:
        return None
    host = host.lower().rstrip(".")
    return host or None


def check_resolved_targets(targets: list[tuple[TargetType, str]]) -> None:
    """
    Resolve name-based targets and refuse any that reach a blocked address.

    HOSTNAME and DOMAIN targets, and URL targets whose host is a name, are
    resolved with getaddrinfo; every returned address is checked against the
    blocked networks (including IPv4 embedded in IPv6). Resolution failure or
    a lookup slower than SCAN_DNS_TIMEOUT_SECONDS fails closed. IP and CIDR
    targets are not resolved.

    The scanners resolve the names again when they run, so a DNS-rebinding
    window between this check and the scan remains; this check stops names
    that plainly point at internal or metadata addresses.

    Raises ScopeViolationError on the first refused target.
    """
    hosts: list[str] = []
    for target_type, value in targets:
        host = _host_to_resolve(target_type, value)
        if host and host not in hosts:
            hosts.append(host)
    if not hosts:
        return

    blocked = blocked_networks()
    timeout = get_settings().SCAN_DNS_TIMEOUT_SECONDS
    executor = ThreadPoolExecutor(max_workers=min(8, len(hosts)), thread_name_prefix="scope-dns")
    try:
        futures = {host: executor.submit(socket.getaddrinfo, host, None) for host in hosts}
        deadline = time.monotonic() + timeout
        for host, future in futures.items():
            try:
                infos = future.result(timeout=max(0.0, deadline - time.monotonic()))
            except (FutureTimeoutError, OSError, UnicodeError):
                # socket.gaierror is an OSError; a hung or failing lookup fails closed.
                raise ScopeViolationError(
                    f"Target {host} could not be resolved to verify that it is allowed"
                ) from None
            for info in infos:
                address = str(info[4][0]).split("%", 1)[0]
                if _is_disallowed(address, blocked):
                    raise ScopeViolationError(
                        f"Target {host} resolves to a blocked address ({address})"
                    )
    finally:
        # Never wait for a hung resolver thread; it exits when the lookup returns.
        executor.shutdown(wait=False, cancel_futures=True)
