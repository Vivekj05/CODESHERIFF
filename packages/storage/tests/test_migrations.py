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
    "patch_proposals",
    "pr_precedents",
    "precedent_chunks",
    "repositories",
    "sessions",
    "users",
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


def test_downgrading_past_0003_folds_superseded_audits_into_failed(
    clean_engine: Engine, alembic_cfg: Callable[[object], Config]
) -> None:
    """`superseded` stops being expressible on the way down, and those rows still have to land.

    The CHECK constraint from 0001 requires a failed audit to say why, so a downgrade that only
    retyped the column would leave rows the constraint rejects. Exercised with a real row because
    the rollback in every other test runs against an empty `audits`, which cannot catch this.
    """
    with clean_engine.begin() as connection:
        command.upgrade(alembic_cfg(connection), "head")
        connection.execute(
            text(
                """
                INSERT INTO installations (id, account_login, account_type)
                VALUES (1, 'acme', 'Organization');
                INSERT INTO repositories (id, installation_id, full_name, default_branch,
                                          is_private, analysis_enabled)
                VALUES (2, 1, 'acme/api', 'main', true, true);
                INSERT INTO audits (id, repository_id, pr_number, base_sha, head_sha, status,
                                    contract_version, prior_probability, alert_threshold)
                VALUES (gen_random_uuid(), 2, 7, 'b', 'a', 'superseded', '2.0.0', 0.05, 0.7);
                """
            )
        )

    with clean_engine.begin() as connection:
        command.downgrade(alembic_cfg(connection), "0002_users_and_sessions")

    with clean_engine.connect() as connection:
        row = connection.execute(text("SELECT status, error_reason FROM audits")).one()
    assert row.status == "failed"
    assert row.error_reason == "superseded by a later head"

    # Back to head, and empty. The session-scoped `migrated_engine` points at this same database,
    # so a test that leaves it downgraded takes every later test with it.
    with clean_engine.begin() as connection:
        command.downgrade(alembic_cfg(connection), "base")
        command.upgrade(alembic_cfg(connection), "head")
