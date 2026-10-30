"""RQ background queues setup and dispatch helpers."""

from __future__ import annotations

import logging
from typing import Any

from app.config import get_settings

logger = logging.getLogger(__name__)

# Seconds a scan job may run beyond SCAN_TIMEOUT (result parsing and normalization).
_SCAN_JOB_MARGIN_SECONDS = 600

_redis_connection: Any | None = None


def get_redis_connection() -> Any:
    """Return the process-wide Redis connection used for queueing."""
    global _redis_connection
    if _redis_connection is None:
        import redis
        _redis_connection = redis.from_url(
            get_settings().redis_url,
            socket_connect_timeout=2,
            health_check_interval=30,
        )
    return _redis_connection


def _job_timeout(queue_name: str) -> int:
    settings = get_settings()
    if queue_name == "reports":
        return settings.REPORT_JOB_TIMEOUT
    return settings.scan_timeout_seconds + _SCAN_JOB_MARGIN_SECONDS


def enqueue_job(queue_name: str, func: Any, *args: Any, **kwargs: Any) -> str:
    """
    Enqueue a background job via RQ.
    If Redis is unavailable, runs asynchronously in a detached thread for dev ease.
    """
    settings = get_settings()
    try:
        from rq import Queue
        conn = get_redis_connection()
        q = Queue(queue_name, connection=conn)
        job = q.enqueue(func, *args, **kwargs, job_timeout=_job_timeout(queue_name))
        return job.id
    except Exception as e:
        if not (settings.is_development or settings.is_testing):
            raise RuntimeError("Background queue is unavailable") from e
        logger.warning("Redis/RQ unavailable (%s); executing via thread pool fallback", e)
        import threading
        t = threading.Thread(target=func, args=args, kwargs=kwargs, daemon=True)
        t.start()
        return f"thread-{t.ident}"
