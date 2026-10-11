"""Access scoping at the SQL level.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

The API tests exercise these through HTTP. These exist because one of them is a security invariant
that should not depend on a route being wired correctly: an empty installation list can never widen
into "everything". Users and sessions are Better Auth's now (D-101) and are not written from Python.
"""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session as DbSession

from codesheriff_storage.identity import (
    list_repositories,
    set_analysis_enabled,
    upsert_installation,
    upsert_repository,
)

pytestmark = pytest.mark.db


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
