"""Fixtures for the API tests.

Two guarantees this file exists to provide.

**No test reaches the network.** An autouse fixture blocks every non-loopback socket connection
unless `CODESHERIFF_ALLOW_LIVE_CALLS` is set. CLAUDE.md requires that tests never make live API
calls; a guard at the socket layer catches the ones a forgotten mock would let through, including
inside `githubkit`.

**GitHub is substituted at the interface, not at the HTTP layer.** `FakeGitHubGateway` implements
`GitHubGateway`, so the real routes run against it. A mocked HTTP response would still pass with a
misspelled endpoint; a fake implementation of the interface would not compile against a changed
signature.
"""

from __future__ import annotations

import os
import socket
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session as DbSession

from codesheriff_api.config import ApiConfig
from codesheriff_api.deps import get_config, get_db, get_github
from codesheriff_api.github_gateway import (
    GitHubError,
    GitHubIdentity,
    InstallationAccount,
    InstallationRepository,
)
from codesheriff_api.main import app
from codesheriff_api.queue import QueueError, get_queue
from codesheriff_storage.testing import migrated_engine, rollback_session, test_database_url

LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


@pytest.fixture(autouse=True)
def block_live_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any connection that is not loopback.

    Loopback stays open because the throwaway Postgres runs there. Set
    `CODESHERIFF_ALLOW_LIVE_CALLS=1` to lift this deliberately — nothing in the suite does.
    """
    if os.environ.get("CODESHERIFF_ALLOW_LIVE_CALLS"):
        return

    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: object) -> object:
        host = address[0] if isinstance(address, tuple) else str(address)
        if str(host) in LOOPBACK:
            return real_connect(self, address)  # type: ignore[arg-type]
        raise RuntimeError(
            f"A test tried to open a live connection to {host!r}. Tests must never make live API "
            f"calls (CLAUDE.md). Substitute GitHubGateway instead."
        )

    monkeypatch.setattr(socket.socket, "connect", guarded)


class FakeGitHubGateway:
    """A GitHub that answers from fixtures and records what it was asked."""

    def __init__(
        self,
        identity: GitHubIdentity | None = None,
        repositories: dict[int, list[InstallationRepository]] | None = None,
        failing_installations: set[int] | None = None,
    ) -> None:
        self.identity = identity or GitHubIdentity(
            github_id=4242,
            login="octo-dev",
            name="Octo Dev",
            avatar_url="https://example.invalid/avatar.png",
            installation_ids=[9001],
        )
        self.repositories = repositories or {
            9001: [
                InstallationRepository(
                    repo_id=5001,
                    full_name="acme/payments-api",
                    default_branch="main",
                    is_private=True,
                ),
                InstallationRepository(
                    repo_id=5002,
                    full_name="acme/internal-tools",
                    default_branch="main",
                    is_private=True,
                ),
            ]
        }
        self.failing_installations = failing_installations or set()
        self.codes_seen: list[str] = []

    def sign_in(self, code: str) -> GitHubIdentity:
        self.codes_seen.append(code)
        if code == "bad-code":
            raise GitHubError("GitHub rejected the code")
        return self.identity

    def get_installation(self, installation_id: int) -> InstallationAccount:
        if installation_id in self.failing_installations:
            raise GitHubError("installation unavailable")
        return InstallationAccount(
            installation_id=installation_id,
            account_login="acme",
            account_type="Organization",
        )

    def list_installation_repositories(self, installation_id: int) -> list[InstallationRepository]:
        if installation_id in self.failing_installations:
            raise GitHubError("installation unavailable")
        return self.repositories.get(installation_id, [])


WEBHOOK_SECRET = "test-webhook-secret"


class FakeTaskQueue:
    """A broker that records what it was asked to publish, and can refuse.

    Substituted at the `TaskQueue` interface for the same reason GitHub is: a test that needed a
    live Redis would either be skipped everywhere or would make the suite depend on a service. What
    matters at this layer is *that* an audit id was published, and exactly once.
    """

    def __init__(self, *, failing: bool = False) -> None:
        self.published: list[uuid.UUID] = []
        self.failing = failing

    def enqueue_audit(self, audit_id: uuid.UUID) -> None:
        if self.failing:
            raise QueueError("broker unreachable")
        self.published.append(audit_id)


@pytest.fixture
def api_config() -> ApiConfig:
    """Configuration with credentials present but never used — the gateway is faked."""
    return ApiConfig(
        GITHUB_APP_ID="123456",
        GITHUB_APP_CLIENT_ID="Iv1.testclientid",
        GITHUB_APP_CLIENT_SECRET="test-client-secret",
        GITHUB_APP_SLUG="codesheriff-test",
        GITHUB_WEBHOOK_SECRET=WEBHOOK_SECRET,
        API_PUBLIC_URL="http://localhost:8000",
        DASHBOARD_ORIGIN="http://localhost:3000",
    )


@pytest.fixture
def queue() -> FakeTaskQueue:
    return FakeTaskQueue()


@pytest.fixture(scope="session")
def db_url() -> str:
    url = test_database_url()
    if not url:
        pytest.skip(
            "CODESHERIFF_TEST_DB is not set. Start Postgres (docker compose up -d postgres) and "
            "point it at a throwaway database to run the db-marked tests."
        )
    return url


@pytest.fixture(scope="session")
def engine(db_url: str) -> Iterator[Engine]:
    with migrated_engine(db_url) as db_engine:
        yield db_engine


@pytest.fixture
def db(engine: Engine) -> Iterator[DbSession]:
    with rollback_session(engine) as session:
        yield session


@pytest.fixture
def github() -> FakeGitHubGateway:
    return FakeGitHubGateway()


@pytest.fixture
def client(
    db: DbSession,
    api_config: ApiConfig,
    github: FakeGitHubGateway,
    queue: FakeTaskQueue,
) -> Iterator[TestClient]:
    """The real app, with configuration, database and GitHub replaced.

    `get_db` yields the rollback-scoped session and swallows the commit: the fixture's transaction
    is what keeps tests isolated, and a real commit inside it would defeat that.
    """

    def _db_override() -> Iterator[DbSession]:
        yield db

    app.dependency_overrides[get_config] = lambda: api_config
    app.dependency_overrides[get_db] = _db_override
    app.dependency_overrides[get_github] = lambda: github
    app.dependency_overrides[get_queue] = lambda: queue
    try:
        with TestClient(app, follow_redirects=False) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()
