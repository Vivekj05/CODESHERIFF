"""Sessions and access scoping at the SQL level.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

The API tests exercise these through HTTP. These exist because two of them are security invariants
that should not depend on a route being wired correctly: a session token is never stored, and an
empty installation list can never widen into "everything".
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from codesheriff_storage.identity import (
    create_session,
    hash_session_token,
    list_repositories,
    purge_expired_sessions,
    revoke_session,
    session_for_token,
    set_analysis_enabled,
    upsert_installation,
    upsert_repository,
    upsert_user,
)
from codesheriff_storage.models import Session as SessionRow
from codesheriff_storage.models import User

pytestmark = pytest.mark.db


@pytest.fixture
def user_id(session: DbSession) -> int:
    user = upsert_user(session, github_id=4242, login="octo", name="Octo", avatar_url=None)
    session.flush()
    return user.id


def make_repo(session: DbSession, installation_id: int, repo_id: int, full_name: str) -> None:
    upsert_installation(
        session,
        installation_id=installation_id,
        account_login=f"acct-{installation_id}",
        account_type="Organization",
    )
    upsert_repository(
        session,
        repo_id=repo_id,
        installation_id=installation_id,
        full_name=full_name,
        default_branch="main",
        is_private=True,
    )


def test_upsert_user_is_idempotent_and_refreshes_identity(session: DbSession) -> None:
    """Signing in twice updates the row rather than colliding on the primary key.

    The GitHub user id is the key, so a renamed account keeps its history instead of arriving as a
    second user.
    """
    first = upsert_user(session, github_id=7, login="old-login", name=None, avatar_url=None)
    second = upsert_user(
        session, github_id=7, login="new-login", name="Renamed", avatar_url="http://a/b"
    )
    session.flush()

    assert first.id == second.id == 7
    assert len(session.execute(select(User)).scalars().all()) == 1
    assert second.login == "new-login"
    assert second.name == "Renamed"
    assert second.last_login_at is not None


def test_only_a_hash_of_the_session_token_is_stored(session: DbSession, user_id: int) -> None:
    row, token = create_session(session, user_id, [9001], ttl=timedelta(hours=8))

    assert row.token_sha256 == hash_session_token(token)
    assert len(row.token_sha256) == 64
    assert token not in row.token_sha256


def test_a_live_token_resolves_and_a_wrong_one_does_not(session: DbSession, user_id: int) -> None:
    _, token = create_session(session, user_id, [9001], ttl=timedelta(hours=8))

    assert session_for_token(session, token) is not None
    assert session_for_token(session, token + "x") is None
    assert session_for_token(session, "") is None


def test_an_expired_session_does_not_resolve(session: DbSession, user_id: int) -> None:
    """Aged the way a session actually ages: created nine hours ago with an eight-hour lifetime.

    `expires_at` cannot simply be dragged into the past — `ck_sessions_expiry_after_creation`
    forbids an expiry that precedes creation, so the row has to be back-dated as a whole.
    """
    row, token = create_session(session, user_id, [9001], ttl=timedelta(hours=8))
    row.created_at = datetime.now(UTC) - timedelta(hours=9)
    row.expires_at = datetime.now(UTC) - timedelta(hours=1)
    session.flush()

    assert session_for_token(session, token) is None


def test_a_revoked_session_does_not_resolve(session: DbSession, user_id: int) -> None:
    _, token = create_session(session, user_id, [9001], ttl=timedelta(hours=8))

    assert revoke_session(session, token) is True
    assert session_for_token(session, token) is None
    assert revoke_session(session, token) is False


def test_purge_removes_only_long_expired_sessions(session: DbSession, user_id: int) -> None:
    live, _ = create_session(session, user_id, [9001], ttl=timedelta(hours=8))
    stale, _ = create_session(session, user_id, [9001], ttl=timedelta(hours=8))
    stale.created_at = datetime.now(UTC) - timedelta(days=4)
    stale.expires_at = datetime.now(UTC) - timedelta(days=3)
    session.flush()

    assert purge_expired_sessions(session) == 1
    assert session.get(SessionRow, live.id) is not None
    assert session.get(SessionRow, stale.id) is None


def test_an_empty_installation_list_sees_nothing(session: DbSession) -> None:
    """The whole access check. A session granted nothing must not fall through to every row."""
    make_repo(session, installation_id=9001, repo_id=5001, full_name="acme/one")
    session.flush()

    assert list_repositories(session, installation_ids=[], limit=50) == []
    assert set_analysis_enabled(session, repo_id=5001, installation_ids=[], enabled=False) is None


def test_listing_is_scoped_to_the_given_installations(session: DbSession) -> None:
    make_repo(session, installation_id=9001, repo_id=5001, full_name="acme/mine")
    make_repo(session, installation_id=9002, repo_id=5002, full_name="other/theirs")
    session.flush()

    mine = list_repositories(session, installation_ids=[9001], limit=50)
    assert [row.full_name for row in mine] == ["acme/mine"]


def test_keyset_pagination_is_stable_across_an_insert_above_the_cursor(
    session: DbSession,
) -> None:
    """The reason for keyset over OFFSET: a new repository mid-scroll must not shift the page."""
    for n in (1, 3, 5):
        make_repo(session, 9001, 5000 + n, f"acme/repo-{n}")
    session.flush()

    first = list_repositories(session, [9001], limit=2)
    assert [r.full_name for r in first] == ["acme/repo-1", "acme/repo-3"]

    # An installation event inserts a repository that sorts *above* the cursor.
    make_repo(session, 9001, 4999, "acme/repo-0")
    session.flush()

    second = list_repositories(session, [9001], limit=2, after_full_name="acme/repo-3")
    assert [r.full_name for r in second] == ["acme/repo-5"]


def test_a_resync_does_not_re_enable_analysis(session: DbSession) -> None:
    make_repo(session, 9001, 5001, "acme/one")
    session.flush()

    set_analysis_enabled(session, repo_id=5001, installation_ids=[9001], enabled=False)
    session.flush()

    # A routine resync from GitHub, with the same values it would send.
    upsert_repository(
        session,
        repo_id=5001,
        installation_id=9001,
        full_name="acme/one",
        default_branch="main",
        is_private=True,
    )
    session.flush()

    rows = list_repositories(session, [9001], limit=10)
    assert rows[0].analysis_enabled is False
