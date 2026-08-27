"""Fixtures for the storage tests.

Tests that need Postgres are marked `db` and skipped unless `CODESHERIFF_TEST_DB` names a database
(D-029). `uv run pytest` therefore stays green on a machine with nothing running, and a developer
who has not started Docker sees skips rather than a wall of connection errors.

pgvector cannot be faked on SQLite, and a schema built from `Base.metadata` is not the schema
production runs — so these tests migrate a real database with Alembic or they do not run at all.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from codesheriff_storage.session import build_engine, build_session_factory

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


def alembic_config(connection: object) -> Config:
    """Alembic config bound to an open connection, so migrations join the test's transaction."""
    config = Config(str(ALEMBIC_INI))
    config.attributes["connection"] = connection
    return config


@pytest.fixture
def alembic_cfg() -> Callable[[object], Config]:
    """`alembic_config` as a fixture, so test modules need no cross-module import."""
    return alembic_config


@pytest.fixture(scope="session")
def db_url() -> str:
    """URL of a throwaway database. Skips the test when it is not set."""
    url = os.environ.get("CODESHERIFF_TEST_DB")
    if not url:
        pytest.skip(
            "CODESHERIFF_TEST_DB is not set. Start Postgres (docker compose up -d postgres) and "
            "point it at a throwaway database to run the db-marked tests."
        )
    return url


@pytest.fixture(scope="session")
def migrated_engine(db_url: str) -> Iterator[Engine]:
    """An engine against a database migrated to head, from empty.

    Downgrades to base first so a leftover schema from an interrupted run cannot make a broken
    migration look like it applied.
    """
    engine = build_engine(url=db_url)
    with engine.begin() as connection:
        command.downgrade(alembic_config(connection), "base")
        command.upgrade(alembic_config(connection), "head")
    yield engine
    with engine.begin() as connection:
        command.downgrade(alembic_config(connection), "base")
    engine.dispose()


@pytest.fixture
def session(migrated_engine: Engine) -> Iterator[Session]:
    """A session whose work is rolled back afterwards, so tests cannot leak rows into each other."""
    connection = migrated_engine.connect()
    transaction = connection.begin()
    factory = build_session_factory(migrated_engine)
    db_session = factory(bind=connection)
    try:
        yield db_session
    finally:
        db_session.close()
        # A test that asserts the database REJECTS a row leaves the session having already rolled
        # back, which deassociates this transaction. Rolling it back again is not an error, but it
        # warns — and a warning in every constraint test trains people to ignore warnings.
        if transaction.is_active:
            transaction.rollback()
        connection.close()


@pytest.fixture
def clean_engine(db_url: str) -> Iterator[Engine]:
    """An engine against a database with no CodeSheriff schema at all.

    For the migration tests themselves, which need to drive upgrade and downgrade rather than
    inherit an already-migrated database.
    """
    engine = build_engine(url=db_url)
    with engine.begin() as connection:
        command.downgrade(alembic_config(connection), "base")
    yield engine
    engine.dispose()
