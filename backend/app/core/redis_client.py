"""
Shared, fail-fast Redis client for request-path features (token revocation,
rate limiting, readiness checks).

The client is created lazily and reused. After a failure, Redis is skipped for a
short period so an outage does not add a connect timeout to every request.
Callers that catch a Redis error should call mark_redis_failed() and fall back
to their in-process behaviour.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from app.config import get_settings

logger = logging.getLogger(__name__)

_REDIS_RETRY_SECONDS = 30.0

_lock = threading.Lock()
_redis_client: Any | None = None
_redis_retry_after = 0.0


def get_redis_safe() -> Any | None:
    """Return the shared Redis client, or None while Redis is unavailable.

    Returns None when the redis package is not installed.
    """
    global _redis_client, _redis_retry_after
    client = _redis_client
    if client is not None:
        return client
    now = time.monotonic()
    if now < _redis_retry_after:
        return None
    with _lock:
        if _redis_client is not None:
            return _redis_client
        if now < _redis_retry_after:
            return None
        try:
            import redis
        except ImportError:
            _redis_retry_after = now + _REDIS_RETRY_SECONDS
            return None
        try:
            conn = redis.from_url(
                get_settings().redis_url, socket_connect_timeout=1, socket_timeout=1
            )
            conn.ping()
        except Exception:
            logger.debug("Redis unavailable; retrying in %.0f seconds", _REDIS_RETRY_SECONDS)
            _redis_retry_after = now + _REDIS_RETRY_SECONDS
            return None
        _redis_client = conn
        return conn


def mark_redis_failed() -> None:
    """Drop the shared client after an error and back off before reconnecting."""
    global _redis_client, _redis_retry_after
    with _lock:
        _redis_client = None
        _redis_retry_after = time.monotonic() + _REDIS_RETRY_SECONDS
