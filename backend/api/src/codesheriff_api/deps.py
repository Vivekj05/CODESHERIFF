"""Dependencies: configuration, a database session, the GitHub gateway, and the current user.

Everything here is overridable through FastAPI's `dependency_overrides`, which is how the test
suite runs the real routes against a fake GitHub and a throwaway database without patching modules.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session as DbSession

from codesheriff_api.config import ApiConfig
from codesheriff_api.github_gateway import GitHubGateway, GitHubKitGateway
from codesheriff_storage import (
    StorageConfig,
    build_engine,
    build_session_factory,
    session_for_token,
    touch_session,
)
from codesheriff_storage.models import Session as SessionRow


@lru_cache(maxsize=1)
def get_config() -> ApiConfig:
    """Configuration, read once per process."""
    return ApiConfig.load()


@lru_cache(maxsize=1)
def _session_factory() -> object:
    """One engine and session factory per process, created on first use.

    Lazily, because importing this module must not require a reachable database — `/health` answers
    without one, and the test suite replaces this dependency wholesale.
    """
    return build_session_factory(build_engine(StorageConfig.load()))


def get_db() -> Iterator[DbSession]:
    """A transactional session per request: commit on success, roll back on any exception."""
    factory = _session_factory()
    db: DbSession = factory()  # type: ignore[operator]
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def get_github(config: Annotated[ApiConfig, Depends(get_config)]) -> GitHubGateway:
    return GitHubKitGateway(config)


def get_current_session(
    db: Annotated[DbSession, Depends(get_db)],
    config: Annotated[ApiConfig, Depends(get_config)],
    codesheriff_session: Annotated[str | None, Cookie()] = None,
) -> SessionRow:
    """Resolve the session cookie, or 401.

    One shape of failure for every cause — absent, unknown, revoked, expired. Telling a caller
    *which* tells an attacker whether a guessed token ever existed.

    The cookie parameter is named for the cookie itself; FastAPI maps
    `codesheriff_session` to `config.session_cookie_name`'s default. Changing the configured name
    without changing this parameter would silently stop reading the cookie, so the name is asserted
    in `test_auth.py`.
    """
    row = session_for_token(db, codesheriff_session or "")
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not signed in.",
            headers={"WWW-Authenticate": "Cookie"},
        )
    touch_session(db, row.id)
    return row


ConfigDep = Annotated[ApiConfig, Depends(get_config)]
DbDep = Annotated[DbSession, Depends(get_db)]
GitHubDep = Annotated[GitHubGateway, Depends(get_github)]
SessionDep = Annotated[SessionRow, Depends(get_current_session)]
