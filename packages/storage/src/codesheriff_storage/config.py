"""Database configuration.

One setting that matters: where Postgres is. Everything else about persistence is schema, and
schema belongs to Alembic.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATABASE_URL = "postgresql+psycopg://codesheriff:codesheriff@localhost:5432/codesheriff"
"""Matches `docker-compose.yml`. psycopg3, and synchronous — see D-028."""


class StorageConfig(BaseSettings):
    """Connection settings, read from the environment or `.env`."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = Field(default=DEFAULT_DATABASE_URL, alias="DATABASE_URL")

    pool_size: int = 5
    max_overflow: int = 5
    pool_pre_ping: bool = True
    """The worker holds connections across long agent runs, and a semantic call can idle behind a
    rate limit for minutes. Without this, the first query after an idle timeout raises rather than
    reconnecting, and an audit fails for a reason that has nothing to do with the code it was
    reviewing."""

    echo_sql: bool = False

    @classmethod
    def load(cls) -> StorageConfig:
        """Load from the environment with defaults."""
        return cls()
