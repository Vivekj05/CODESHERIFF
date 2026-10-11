"""Fixtures for the worker tests.

Same two guarantees as `apps/api/tests/conftest.py`, for the same reasons.

**No test reaches the network.** An autouse fixture blocks every non-loopback socket connection
unless `CODESHERIFF_ALLOW_LIVE_CALLS` is set. This process is the one that posts to real pull
requests, so a forgotten mock here would comment on somebody's repository.

**GitHub is substituted at the interface.** `FakeGitHubGateway` implements `GitHubGateway`, so the
task runs its real code path. It records the exact body it was given, which is what lets a test
assert that no probability reached the comment.

The Celery app itself is never started. `execute_audit` takes its session factory and its gateway
as arguments precisely so the pipeline can be tested without a broker.

**These tests commit for real, and clean up afterwards.** `apps/api` and `packages/storage` isolate
tests inside a transaction that is rolled back, which works because a request handler commits once
at the end. The worker does not: it claims an audit in one transaction, commits, and records the
outcome in another — which is the behaviour under test, since a crash between the two is exactly
what `claim_audit` and `fail_audit` exist to survive. Wrapping that in an outer transaction would
test a different program.
"""

from __future__ import annotations

import os
import socket
from collections.abc import Iterator
from dataclasses import dataclass

import pytest
from sqlalchemy import Engine, delete
from sqlalchemy.orm import Session as DbSession
from sqlalchemy.orm import sessionmaker

from codesheriff_storage import build_session_factory
from codesheriff_storage.models import Audit, CalibrationRun, Installation, Repository
from codesheriff_storage.testing import migrated_engine, test_database_url
from codesheriff_worker.github_gateway import GitHubError, PullRequestFile

LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


@pytest.fixture(autouse=True)
def block_live_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any connection that is not loopback."""
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


@dataclass
class PostedComment:
    installation_id: int
    repo_full_name: str
    pr_number: int
    body: str
    comment_id: int | None


@dataclass
class PostedReviewComment:
    """One anchored suggestion, as the gateway was asked to post it.

    The anchor is recorded separately from the body because the two are checked by different
    tests: that the lines are inside the diff (D-095), and that the body names no file (D-050).
    """

    installation_id: int
    repo_full_name: str
    pr_number: int
    commit_sha: str
    path: str
    start_line: int
    line: int
    body: str


class FakeGitHubGateway:
    """A GitHub that serves the blobs it was given and records every comment it was asked for.

    `blobs` is keyed by `(ref, path)` so a test can give a file a different body on the base and
    head commits, which is the only way to exercise extraction's diffing. A key that is absent
    returns None, exactly as the real gateway does for a file that is not at that ref — so an
    added file needs no special setup beyond leaving its base key out.
    """

    def __init__(
        self,
        *,
        failing: bool = False,
        next_id: int = 5100,
        files: list[PullRequestFile] | None = None,
        blobs: dict[tuple[str, str], str] | None = None,
    ) -> None:
        self.posted: list[PostedComment] = []
        self.review_comments: list[PostedReviewComment] = []
        self.review_comments_fail = False
        """Set to make every review comment fail. A suggestion GitHub refuses must not cost the
        audit its summary comment, and that is only assertable if the failure can be provoked."""
        self.failing = failing
        self._next_id = next_id
        self.files = files or []
        self.blobs = blobs or {}
        self.fetched: list[tuple[str, str]] = []
        """Every (ref, path) asked for, in order. A test asserts on what was *not* fetched: a
        deleted or non-Python file must cost no API call."""

    def list_pull_request_files(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
    ) -> list[PullRequestFile]:
        if self.failing:
            raise RuntimeError("GitHub is unreachable")
        return list(self.files)

    def get_file_at_ref(
        self,
        installation_id: int,
        repo_full_name: str,
        path: str,
        ref: str,
    ) -> str | None:
        if self.failing:
            raise RuntimeError("GitHub is unreachable")
        self.fetched.append((ref, path))
        return self.blobs.get((ref, path))

    def post_or_update_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        body: str,
        comment_id: int | None = None,
    ) -> int:
        if self.failing:
            raise RuntimeError("GitHub is unreachable")
        self.posted.append(
            PostedComment(installation_id, repo_full_name, pr_number, body, comment_id)
        )
        if comment_id is not None:
            return comment_id
        self._next_id += 1
        return self._next_id

    def post_review_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        commit_sha: str,
        path: str,
        start_line: int,
        line: int,
        body: str,
    ) -> int:
        if self.failing or self.review_comments_fail:
            raise GitHubError("GitHub refused the review comment")
        self.review_comments.append(
            PostedReviewComment(
                installation_id, repo_full_name, pr_number, commit_sha, path, start_line, line, body
            )
        )
        self._next_id += 1
        return self._next_id


@pytest.fixture
def gateway() -> FakeGitHubGateway:
    return FakeGitHubGateway()


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
def factory(engine: Engine) -> sessionmaker[DbSession]:
    """The real session factory the task uses in production."""
    return build_session_factory(engine)


@pytest.fixture
def db(factory: sessionmaker[DbSession]) -> Iterator[DbSession]:
    """A committing session for fixtures and assertions, with the rows removed afterwards.

    Deleting is the price of letting the task commit for real. `installations` cascades to
    repositories and audits, so the order below is only about `calibration_runs`, which nothing
    cascades from — an audit references it with ON DELETE RESTRICT, deliberately (D-026).
    """
    session = factory()
    try:
        yield session
    finally:
        session.rollback()
        for model in (Audit, Repository, Installation, CalibrationRun):
            session.execute(delete(model))
        session.commit()
        session.close()
