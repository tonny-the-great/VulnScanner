"""
Fixed-window rate limiting without third-party dependencies.

Counters live in Redis when it is reachable, so all API processes share them.
Otherwise each API process keeps its own in-memory counters, which still bounds
brute-force attempts per process.

Identifiers (client IPs, user ids) are hashed before they are used as keys.

Usage as a FastAPI dependency:
    @router.post("/login", dependencies=[Depends(rate_limit_by_ip("login", "LOGIN_RATE_LIMIT"))])
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import threading
import time
from collections.abc import Callable

from fastapi import Depends, Request

from app.config import Settings, get_settings
from app.core.exceptions import RateLimitExceededError
from app.core.redis_client import get_redis_safe, mark_redis_failed
from app.core.request_context import get_client_ip
from app.core.security import get_current_user
from app.models.user import User

logger = logging.getLogger(__name__)

_RATE_PATTERN = re.compile(r"([1-9][0-9]*)/(second|minute|hour|day)s?", re.IGNORECASE)
_PERIOD_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}

# In-process fallback: key -> [count, window end timestamp]
_LOCAL_PURGE_THRESHOLD = 10_000
_local_lock = threading.Lock()
_local_counters: dict[str, list[float]] = {}


def parse_rate(spec: str) -> tuple[int, int]:
    """Parse '<count>/<unit>' (unit: second, minute, hour or day; plural allowed)."""
    match = _RATE_PATTERN.fullmatch(spec.strip())
    if not match:
        raise ValueError(f"Invalid rate limit {spec!r}; expected e.g. '10/minute'")
    return int(match.group(1)), _PERIOD_SECONDS[match.group(2).lower()]


def _hit_local(key: str, window_end: float, now: float) -> int:
    with _local_lock:
        if len(_local_counters) > _LOCAL_PURGE_THRESHOLD:
            expired = [k for k, (_, end) in _local_counters.items() if end <= now]
            for k in expired:
                del _local_counters[k]
        entry = _local_counters.get(key)
        if entry is None:
            entry = _local_counters[key] = [0, window_end]
        entry[0] += 1
        return int(entry[0])


def hit(
    bucket: str,
    identifier: str,
    spec: str,
    *,
    now: float | None = None,
) -> tuple[bool, int]:
    """Count one request; return (allowed, seconds until the window resets)."""
    limit, period = parse_rate(spec)
    current = time.time() if now is None else now
    window = int(current // period)
    digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()[:32]
    key = f"ratelimit:{bucket}:{digest}:{window}"
    window_end = (window + 1) * period
    retry_after = max(1, math.ceil(window_end - current))

    count: int | None = None
    conn = get_redis_safe()
    if conn is not None:
        try:
            count = int(conn.incr(key))
            if count == 1:
                conn.expire(key, period + 1)
        except Exception:
            mark_redis_failed()
            count = None
    if count is None:
        count = _hit_local(key, window_end, current)
    return count <= limit, retry_after


def enforce_rate_limit(bucket: str, identifier: str | None, spec: str) -> None:
    """Raise RateLimitExceededError when the identifier exceeded its limit in this bucket."""
    if not get_settings().RATE_LIMIT_ENABLED or not identifier:
        return
    allowed, retry_after = hit(bucket, identifier, spec)
    if not allowed:
        logger.info("Rate limit exceeded for bucket %s", bucket)
        raise RateLimitExceededError(retry_after)


def reset_rate_limits() -> None:
    """Clear the in-process counters (tests, or after changing limits at runtime)."""
    with _local_lock:
        _local_counters.clear()


def _require_setting(setting_name: str) -> None:
    if setting_name not in Settings.model_fields:
        raise ValueError(f"Unknown rate limit setting {setting_name!r}")


def rate_limit_by_ip(bucket: str, setting_name: str) -> Callable[[Request], None]:
    """Dependency limiting requests per client IP; the limit is read on every call."""
    _require_setting(setting_name)

    def _dep(request: Request) -> None:
        enforce_rate_limit(
            bucket,
            get_client_ip(request) or "unknown",
            getattr(get_settings(), setting_name),
        )

    return _dep


def rate_limit_by_user(bucket: str, setting_name: str) -> Callable[..., None]:
    """Dependency limiting requests per authenticated user; the limit is read on every call."""
    _require_setting(setting_name)

    def _dep(user: User = Depends(get_current_user)) -> None:
        enforce_rate_limit(bucket, str(user.id), getattr(get_settings(), setting_name))

    return _dep
