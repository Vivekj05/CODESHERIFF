"""Dependencies: configuration, a database session, the GitHub gateway, and the current caller.

Everything here is overridable through FastAPI's `dependency_overrides`, which is how the test
suite runs the real routes against a fake GitHub, a throwaway database and a locally signed token
without patching modules.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session as DbSession

from codesheriff_api.config import ApiConfig
from codesheriff_api.github_gateway import GitHubGateway, GitHubKitGateway
from codesheriff_api.principal import (
    InvalidTokenError,
    Principal,
    TokenVerifier,
    VerifierUnavailableError,
    jwks_verifier,
)
from codesheriff_storage import StorageConfig, build_engine, build_session_factory


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


@lru_cache(maxsize=4)
def _verifier_for(jwks_url: str, issuer: str, cache_seconds: int) -> TokenVerifier:
    # Keyed on the values, not the config object, so the JWKS cache survives across requests.
    return jwks_verifier(jwks_url=jwks_url, issuer=issuer, cache_seconds=cache_seconds)


def get_token_verifier(config: Annotated[ApiConfig, Depends(get_config)]) -> TokenVerifier:
    return _verifier_for(config.jwks_url, config.token_issuer, config.jwks_cache_seconds)


def get_current_principal(
    verifier: Annotated[TokenVerifier, Depends(get_token_verifier)],
    authorization: Annotated[str | None, Header()] = None,
) -> Principal:
    """Verify the caller's Better Auth JWT, or 401 (D-101).

    One shape of failure for every cause: absent, forged, expired, wrong issuer, malformed. Telling
    a caller which tells an attacker what to fix. The one exception is a JWKS that cannot be
    fetched, which is 503: that is this deployment failing, and calling it "not signed in" would
    send a signed-in user round a sign-in loop that cannot succeed.
    """
    scheme, _, token = (authorization or "").partition(" ")
    try:
        if scheme.lower() != "bearer":
            raise InvalidTokenError("no bearer token")
        return verifier.verify(token.strip())
    except VerifierUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="The sign-in service's signing keys could not be fetched.",
        ) from exc
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not signed in.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


ConfigDep = Annotated[ApiConfig, Depends(get_config)]
DbDep = Annotated[DbSession, Depends(get_db)]
GitHubDep = Annotated[GitHubGateway, Depends(get_github)]
SessionDep = Annotated[Principal, Depends(get_current_principal)]
"""The verified caller. Named for what routes used to receive; it is a token now, not a row."""
