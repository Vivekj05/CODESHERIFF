"""Engine and session factory. Synchronous, by decision (D-028).

Celery is synchronous and owns the pipeline; the API only enqueues until the dashboard arrives in
Chapter 15. An async stack would mean two engines, two session factories and two test harnesses to
serve one real consumer. When the dashboard's read path justifies it, an async engine can be added
beside this one — the models are shared either way.

There is no `create_all` here on purpose. Alembic owns the schema, including in tests: a schema
built from metadata is not the schema production runs, and the difference is exactly where a
missing migration hides.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from codesheriff_storage.config import StorageConfig


def build_engine(config: StorageConfig | None = None, url: str | None = None) -> Engine:
    """Create an engine from config, or from an explicit URL (tests, migrations)."""
    cfg = config or StorageConfig.load()
    return create_engine(
        url or cfg.database_url,
        pool_size=cfg.pool_size,
        max_overflow=cfg.max_overflow,
        pool_pre_ping=cfg.pool_pre_ping,
        echo=cfg.echo_sql,
        future=True,
    )


def build_session_factory(engine: Engine) -> sessionmaker[Session]:
    """Session factory for one engine.

    `expire_on_commit=False` so a worker can keep reading a row it just wrote — the pipeline
    commits an audit and then goes on to use its id — without a second round trip per attribute.
    """
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


@contextmanager
def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    """Transactional scope: commit on success, roll back on any exception, always close.

    The rollback is not a formality. The CHECK constraints in `models.py` fail an INSERT that
    violates a contract invariant, and a half-written audit that survived that failure would be
    evidence of nothing while looking like evidence of something.
    """
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
