"""Helpers for tests that need a real database.

Shipped in the package rather than duplicated in each `tests/conftest.py`: `packages/storage` and
`apps/api` both need a migrated throwaway database and a session that rolls back, and two copies of
that setup drift apart until one of them is subtly wrong.

Imports no pytest. The skip decision and the fixtures stay in each `conftest.py`, where they belong;
this module only knows how to migrate a database and hand out a session.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from codesheriff_storage.session import build_engine, build_session_factory

TEST_DB_ENV_VAR = "CODESHERIFF_TEST_DB"

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
"""`packages/storage/alembic.ini`, reached from `src/codesheriff_storage/testing.py`."""


def test_database_url() -> str | None:
    """The throwaway database URL, or None when the `db`-marked tests should skip (D-029)."""
    return os.environ.get(TEST_DB_ENV_VAR) or None


def alembic_config(connection: object) -> Config:
    """Alembic config bound to an open connection, so migrations join the caller's transaction."""
    config = Config(str(ALEMBIC_INI))
    config.attributes["connection"] = connection
    return config


@contextmanager
def migrated_engine(url: str) -> Iterator[Engine]:
    """An engine against `url`, migrated to head from empty, and torn back down to base.

    Downgrades first so a schema left behind by an interrupted run cannot make a broken migration
    look like it applied. Alembic builds the schema, never `Base.metadata.create_all` — a schema
    built from metadata is not the schema production runs, and the difference is where a missing
    migration hides.
    """
    engine = build_engine(url=url)
    try:
        with engine.begin() as connection:
            command.downgrade(alembic_config(connection), "base")
            command.upgrade(alembic_config(connection), "head")
        yield engine
    finally:
        with engine.begin() as connection:
            command.downgrade(alembic_config(connection), "base")
        engine.dispose()


@contextmanager
def rollback_session(engine: Engine) -> Iterator[Session]:
    """A session whose work is discarded, so tests cannot leak rows into each other."""
    connection = engine.connect()
    transaction = connection.begin()
    factory = build_session_factory(engine)
    session = factory(bind=connection)
    try:
        yield session
    finally:
        session.close()
        # A test asserting that the database REJECTS a row leaves the session having already rolled
        # back, which deassociates this transaction; rolling it back again only warns.
        if transaction.is_active:
            transaction.rollback()
        connection.close()
