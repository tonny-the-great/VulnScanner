"""
Database migrations (Alembic).

The API applies pending migrations at startup with upgrade_database(). To change the
schema, edit the models, then from the backend directory run
``alembic revision --autogenerate -m "<what changed>"`` and review the generated file.
"""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, text

MIGRATIONS_DIR = Path(__file__).resolve().parent

# Arbitrary constant: API processes starting together take turns migrating (PostgreSQL).
_MIGRATION_LOCK_ID = 7_465_201


def alembic_config() -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS_DIR))
    config.set_main_option("path_separator", "os")
    return config


def head_revision() -> str | None:
    return ScriptDirectory.from_config(alembic_config()).get_current_head()


def current_revision(engine: Engine) -> str | None:
    with engine.connect() as connection:
        return MigrationContext.configure(connection).get_current_revision()


def upgrade_database(engine: Engine) -> None:
    """
    Apply pending migrations in one transaction.

    A database created before migrations existed is adopted by the baseline revision,
    which creates only the tables, indexes and enum types it is missing.
    """
    config = alembic_config()
    with engine.begin() as connection:
        if connection.dialect.name == "postgresql":
            lock = text("SELECT pg_advisory_xact_lock(:id)")
            connection.execute(lock, {"id": _MIGRATION_LOCK_ID})
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
