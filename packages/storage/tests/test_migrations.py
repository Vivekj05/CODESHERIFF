"""The Chapter 3 acceptance criteria that need a live database.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import Engine, inspect, text

from codesheriff_storage.models import Base

pytestmark = pytest.mark.db

EXPECTED_TABLES = {
    "alembic_version",
    "audits",
    "calibration_runs",
    "change_units",
    "evidence",
    "findings",
    "installations",
    "pr_precedents",
    "precedent_chunks",
    "repositories",
}


def test_migrations_apply_to_a_clean_database(
    clean_engine: Engine, alembic_cfg: Callable[[object], Config]
) -> None:
    with clean_engine.begin() as connection:
        command.upgrade(alembic_cfg(connection), "head")

    tables = set(inspect(clean_engine).get_table_names())
    assert tables >= EXPECTED_TABLES, f"missing: {EXPECTED_TABLES - tables}"


def test_migrations_roll_back_cleanly(
    clean_engine: Engine, alembic_cfg: Callable[[object], Config]
) -> None:
    """Downgrade must leave nothing behind — including the enum types.

    A downgrade that drops tables but leaks `audit_status` makes the next upgrade fail with
    "type already exists", which looks like a broken migration and is really a broken rollback.
    """
    with clean_engine.begin() as connection:
        command.upgrade(alembic_cfg(connection), "head")
        command.downgrade(alembic_cfg(connection), "base")

    tables = set(inspect(clean_engine).get_table_names())
    assert not (EXPECTED_TABLES - {"alembic_version"}) & tables

    with clean_engine.begin() as connection:
        command.upgrade(alembic_cfg(connection), "head")

    assert set(inspect(clean_engine).get_table_names()) >= EXPECTED_TABLES


def test_pgvector_extension_is_enabled_by_the_migration(
    clean_engine: Engine, alembic_cfg: Callable[[object], Config]
) -> None:
    """Not left to docker-compose: its init script runs only on a fresh volume, never in CI."""
    with clean_engine.begin() as connection:
        command.upgrade(alembic_cfg(connection), "head")

    with clean_engine.connect() as connection:
        installed = connection.execute(
            text("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
        ).scalar()
    assert installed == 1


def test_no_pending_schema_changes(migrated_engine: Engine) -> None:
    """The migrated database must match the models.

    This is the drift test. The migration writes its CWE list and constraints out literally, on
    purpose — a migration is a historical record. Without this comparison, a model edit in a later
    chapter would apply to nothing and every test would still pass.
    """
    with migrated_engine.connect() as connection:
        context = MigrationContext.configure(
            connection,
            opts={"compare_type": True, "compare_server_default": True},
        )
        diff = compare_metadata(context, Base.metadata)

    assert diff == [], f"models and migrations have drifted: {diff}"
