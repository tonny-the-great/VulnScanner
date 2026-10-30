"""Production must fail visibly instead of spawning an undurable job."""

import pytest

from app.config import get_settings
from app.worker import queues


def test_production_queue_failure_does_not_run_job(monkeypatch):
    def unavailable():
        raise RuntimeError("Redis unavailable")

    monkeypatch.setattr(get_settings(), "ENVIRONMENT", "production")
    monkeypatch.setattr(queues, "get_redis_connection", unavailable)
    calls = []
    with pytest.raises(RuntimeError, match="Background queue is unavailable"):
        queues.enqueue_job("scans", lambda: calls.append(True))
    assert calls == []
