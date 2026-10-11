"""Alembic environment.

Resolves the database URL in one place, in this order:

1. `-x db_url=...` — how the test suite points at its throwaway database
2. `config.attributes["connection"]` — an existing connection, for programmatic runs
3. `DATABASE_URL` / `StorageConfig` — normal operation

`alembic.ini` deliberately carries no `sqlalchemy.url`. A URL sitting in a checked-in config file
is a migration waiting to be run against the wrong host.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import Connection, engine_from_config, pool

from codesheriff_storage.config import StorageConfig
from codesheriff_storage.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    x_args = context.get_x_argument(as_dictionary=True)
    if x_args.get("db_url"):
        return str(x_args["db_url"])
    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url
    return StorageConfig.load().database_url


def _run(connection: Connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_offline() -> None:
    """Emit SQL without a connection (`alembic upgrade head --sql`)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run against a live database."""
    existing = config.attributes.get("connection")
    if existing is not None:
        _run(existing)
        return

    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        _run(connection)


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
