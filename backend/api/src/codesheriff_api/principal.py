"""Who is calling: a Better Auth JWT, verified (D-101).

The dashboard signs users in with Better Auth and sends this API a short-lived JWT in the
`Authorization: Bearer` header. Verifying it is the only thing standing between a request and
someone else's audits, so it is done in one place and fails closed:

- the signature must check out against a key from Better Auth's JWKS, and only EdDSA is accepted,
  so a token cannot choose a weaker algorithm (or `none`) for itself;
- `iss` and `aud` must both be the dashboard's origin, and `exp`, `iat` and `sub` must be present;
- `installation_ids` must be a list of integers. Anything else is a malformed token, not an empty
  list, because an empty list is a real answer (the user sees nothing) and must stay distinguishable
  from a token that never said.

**This API never reads Better Auth's tables.** The token carries everything a route needs. A
database read here would couple the two processes to one schema and turn a key rotation into a
migration.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient, PyJWKClientConnectionError, PyJWKClientError

logger = logging.getLogger(__name__)

ACCEPTED_ALGORITHMS = ["EdDSA"]
"""Better Auth's default (Ed25519). Pinned rather than read from the token header."""


class InvalidTokenError(Exception):
    """The token is absent, forged, expired, for someone else, or malformed. One shape for all."""


class VerifierUnavailableError(Exception):
    """The signing keys could not be fetched, so no token can be checked either way."""


@dataclass(frozen=True)
class Principal:
    """A verified caller. Everything a route may know about who is asking."""

    user_id: str
    login: str
    name: str | None
    avatar_url: str | None
    visible_installation_ids: tuple[int, ...]
    """The installations of this App the user could reach at sign-in (D-035). Every query is scoped
    by these; an empty tuple sees nothing."""

    expires_at: datetime


class TokenVerifier(Protocol):
    def verify(self, token: str) -> Principal: ...


class JwtVerifier:
    """Verifies Better Auth's JWTs. `signing_key_for` maps a token to the key that should sign it.

    Production passes a `PyJWKClient` lookup; the test suite passes a local key, so no test fetches
    anything over the network.
    """

    def __init__(self, *, issuer: str, signing_key_for: Callable[[str], Any]) -> None:
        self._issuer = issuer
        self._signing_key_for = signing_key_for

    def verify(self, token: str) -> Principal:
        if not token:
            raise InvalidTokenError("no token")
        try:
            key = self._signing_key_for(token)
        except PyJWKClientConnectionError as exc:
            raise VerifierUnavailableError(str(exc)) from exc
        except (PyJWKClientError, jwt.PyJWTError) as exc:
            raise InvalidTokenError(f"no signing key: {type(exc).__name__}") from exc

        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=ACCEPTED_ALGORITHMS,
                issuer=self._issuer,
                audience=self._issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(type(exc).__name__) from exc

        return _principal_from(claims)


def _principal_from(claims: dict[str, Any]) -> Principal:
    ids = claims.get("installation_ids")
    if not isinstance(ids, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) for item in ids
    ):
        raise InvalidTokenError("installation_ids is missing or not a list of integers")

    login = claims.get("login")
    if not isinstance(login, str) or not login:
        raise InvalidTokenError("login is missing")

    name = claims.get("name")
    avatar = claims.get("avatar_url")
    return Principal(
        user_id=str(claims["sub"]),
        login=login,
        name=name if isinstance(name, str) else None,
        avatar_url=avatar if isinstance(avatar, str) else None,
        visible_installation_ids=tuple(ids),
        expires_at=datetime.fromtimestamp(int(claims["exp"]), tz=UTC),
    )


def jwks_verifier(*, jwks_url: str, issuer: str, cache_seconds: int) -> JwtVerifier:
    """The production verifier: keys fetched from Better Auth's JWKS and cached."""
    client = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=cache_seconds, timeout=5)
    return JwtVerifier(
        issuer=issuer,
        signing_key_for=lambda token: client.get_signing_key_from_jwt(token).key,
    )
