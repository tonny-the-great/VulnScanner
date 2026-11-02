"""Database migrations: the migrated schema matches the models, and older databases are adopted.

Runs on SQLite, and on PostgreSQL too when VULNSCANNER_TEST_POSTGRES_URL points to a
disposable database (everything in its public schema is dropped).
"""

import os
import uuid

import pytest
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

from app.migrations import current_revision, head_revision, upgrade_database
from app.models import Base
from app.models.organization import Organization

POSTGRES_URL = os.environ.get("VULNSCANNER_TEST_POSTGRES_URL")


def _reset_postgres(engine) -> None:
    with engine.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))


@pytest.fixture(params=["sqlite", "postgresql"])
def empty_engine(request, tmp_path):
    if request.param == "sqlite":
        engine = create_engine(f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}")
    else:
        if not POSTGRES_URL:
            pytest.skip("VULNSCANNER_TEST_POSTGRES_URL is not set")
        engine = create_engine(POSTGRES_URL)
        _reset_postgres(engine)
    yield engine
    if request.param == "postgresql":
        _reset_postgres(engine)
    engine.dispose()


def _schema_differences(engine) -> list:
    with engine.connect() as conn:
        context = MigrationContext.configure(conn, opts={"compare_type": True})
        return compare_metadata(context, Base.metadata)


def test_migrations_build_the_schema_the_models_describe(empty_engine):
    upgrade_database(empty_engine)
    upgrade_database(empty_engine)  # nothing pending: a no-op
    assert current_revision(empty_engine) == head_revision()
    # A difference here means a model changed without a migration: run
    # `alembic revision --autogenerate -m "..."` in backend/ and review the result.
    assert _schema_differences(empty_engine) == []


def test_database_created_before_migrations_is_adopted_with_its_data(empty_engine):
    # What earlier versions left behind: tables from create_all(), possibly without
    # tables and indexes added later, and no migration history.
    Base.metadata.create_all(empty_engine)
    with empty_engine.begin() as conn:
        conn.execute(text("DROP TABLE scan_findings"))
        conn.execute(text("DROP INDEX ix_scan_events_scan_id_created_at"))
    slug = f"adopted-{uuid.uuid4().hex[:8]}"
    with Session(empty_engine) as session:
        session.add(Organization(name="Existing Org", slug=slug))
        session.commit()

    upgrade_database(empty_engine)

    assert current_revision(empty_engine) == head_revision()
    inspector = inspect(empty_engine)
    assert "scan_findings" in inspector.get_table_names()
    assert "ix_scan_events_scan_id_created_at" in {
        index["name"] for index in inspector.get_indexes("scan_events")
    }
    with Session(empty_engine) as session:
        name = session.scalars(select(Organization.name).where(Organization.slug == slug)).one()
    assert name == "Existing Org"
    assert _schema_differences(empty_engine) == []
