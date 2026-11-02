"""Pytest root configuration and test environment setup."""

import os
import tempfile
from pathlib import Path

_test_directory = tempfile.TemporaryDirectory(prefix="vulnscanner-tests-")

# Set environment variables for tests before importing app modules
os.environ["SESSION_SECRET"] = "test-secret-key-NOT-for-production-testing-only-32chars"
os.environ["DATABASE_URL"] = "sqlite:///" + (Path(_test_directory.name) / "test.db").as_posix()
os.environ["UPLOAD_DIR"] = str(Path(_test_directory.name) / "uploads")
os.environ["REDIS_URL"] = "redis://localhost:6379/1"
os.environ["ENVIRONMENT"] = "testing"
os.environ["FIRST_SUPERUSER_EMAIL"] = "admin@example.com"
# Must satisfy the password policy (12+ characters, not containing "admin").
os.environ["FIRST_SUPERUSER_PASSWORD"] = "Platform-Bootstrap-Secret-2026!"
# Tests log in and register far more often than the production limits allow;
# rate limiting itself is covered by tests that enable it explicitly.
os.environ["RATE_LIMIT_ENABLED"] = "false"

import pytest  # noqa: E402
from sqlalchemy import event  # noqa: E402

from app.database import SessionLocal, engine  # noqa: E402
from app.migrations import upgrade_database  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    upgrade_database(engine)
    yield
    # Cleanup after test run
    engine.dispose()
    _test_directory.cleanup()


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


class QueryCounter:
    """SQL statements executed on the test engine (from any thread) while active."""

    def __init__(self):
        self.statements: list[str] = []

    @property
    def count(self) -> int:
        return len(self.statements)

    def reset(self) -> None:
        self.statements.clear()


@pytest.fixture
def query_counter():
    counter = QueryCounter()

    def before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        counter.statements.append(statement)

    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    try:
        yield counter
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute)
