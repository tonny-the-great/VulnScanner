"""
Target validation and normalization module.

CRITICAL SECURITY COMPONENT:
All user-supplied target strings MUST pass through this validator before
being stored as AuthorizedTarget or passed to any scanner command builder.

Rejects:
- Shell metacharacters (;&|`$><"'\n\r\t, etc.)
- Whitespace or control characters
- Invalid IP/CIDR/hostname formats
- Excessively broad CIDR ranges (e.g., /0 through /15 for IPv4)
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.core.exceptions import ValidationError
from app.models.authorization import TargetType

# Strictly allow alphanumeric, dots, hyphens for hostnames/domains
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
SINGLE_LABEL_HOST_REGEX = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)

# Reject any dangerous shell or injection characters
DANGEROUS_CHARS = set(";&|`$><\"'\\\t\r\n\x00{}[]()~*!#?^=")


def validate_and_normalize_target(raw_target: str) -> tuple[TargetType, str]:
    """
    Validate target string and return (TargetType, canonical_value).

    Raises ValidationError if the target format is invalid, dangerous,
    or out-of-bounds.
    """
    if not raw_target:
        raise ValidationError("Target cannot be empty")

    target = raw_target.strip()
    if len(target) > 512:
        raise ValidationError("Target string exceeds maximum length of 512 characters")

    # Check for dangerous metacharacters
    for char in target:
        if char in DANGEROUS_CHARS or ord(char) < 32 or ord(char) > 126:
            raise ValidationError(f"Target contains forbidden character: {repr(char)}")

    if " " in target:
        raise ValidationError("Target contains spaces")

    # 1. Try URL
    if target.startswith(("http://", "https://")):
        try:
            parsed = urlparse(target)
            if not parsed.hostname:
                raise ValidationError("Invalid URL: missing hostname")
            # Recursively validate the hostname portion
            validate_and_normalize_target(parsed.hostname)
            # Reconstruct clean canonical URL (scheme + netloc + path without query/fragment)
            canonical_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path or ''}".rstrip("/")
            return TargetType.URL, canonical_url
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Invalid URL target: {e}") from e

    # 2. Try IPv4 / IPv6 Single Address
    try:
        ip = ipaddress.ip_address(target)
        if isinstance(ip, ipaddress.IPv4Address):
            return TargetType.IPV4, str(ip)
        else:
            return TargetType.IPV6, ip.exploded
    except ValueError:
        pass

    # 3. Try IPv4 / IPv6 CIDR
    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                if net.prefixlen < 16:
                    raise ValidationError(
                        f"IPv4 CIDR prefix /{net.prefixlen} is too broad. "
                        "Minimum allowed prefix is /16"
                    )
                return TargetType.IPV4_CIDR, str(net)
            else:
                if net.prefixlen < 48:
                    raise ValidationError(
                        f"IPv6 CIDR prefix /{net.prefixlen} is too broad. "
                        "Minimum allowed prefix is /48"
                    )
                return TargetType.IPV6_CIDR, str(net)
        except ValueError as e:
            raise ValidationError(f"Invalid CIDR network: {e}") from e

    # 4. Hostname / Domain
    lower_target = target.lower()
    if HOSTNAME_REGEX.match(lower_target) or SINGLE_LABEL_HOST_REGEX.match(lower_target):
        # Decide domain vs hostname: if multiple labels and valid TLD, domain/hostname
        if "." in lower_target:
            return TargetType.DOMAIN, lower_target
        return TargetType.HOSTNAME, lower_target

    raise ValidationError(
        f"Target '{target}' is not a valid IPv4, IPv6, CIDR, hostname, or URL"
    )
