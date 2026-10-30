"""
SQLAlchemy engine + session factory.

Supports SQLite (local dev) and PostgreSQL (production) via DATABASE_URL.
"""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

settings = get_settings()

# ── Engine ────────────────────────────────────────────────────────────────────
_connect_args: dict = {}
_pool_args: dict[str, Any] = {}
if settings.DATABASE_URL.startswith("sqlite"):
    _connect_args["check_same_thread"] = False
else:
    # Queue pool sizing for server databases; each API/worker process has its own pool.
    _pool_args.update(
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
    )

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    # Pool settings — reasonable defaults for a medium-traffic API
    pool_pre_ping=True,    # detect stale connections
    pool_recycle=3600,     # recycle connections after 1 hour
    echo=settings.SQL_ECHO,  # opt-in: statements include sensitive parameters
    **_pool_args,
)

# SQLite: enforce foreign keys (disabled by default in SQLite)
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _connection_record):  # type: ignore[no-untyped-def]
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── FastAPI dependency ────────────────────────────────────────────────────────
def get_db() -> Generator[Session, None, None]:
    """Yield a database session; always close on exit."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """Context manager for standalone worker tasks and scripts."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
