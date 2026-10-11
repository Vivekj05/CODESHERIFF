"""The GitHub App page's read: connected installations, scoped and with history kept (D-102).

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as DbSession

from codesheriff_api.github_gateway import InstallationRepository
from codesheriff_storage import mark_installation_uninstalled, mark_repositories_removed

from .conftest import FakeGitHubGateway, sign_in

pytestmark = pytest.mark.db


def test_it_needs_a_token(client: TestClient) -> None:
    assert client.get("/installations").status_code == 401


def test_a_user_with_no_installations_has_nothing_connected(client: TestClient) -> None:
    sign_in(client, installation_ids=[])
    body = client.get("/installations").json()
    assert body["items"] == []
    assert body["install_url"] == "https://github.com/apps/codesheriff-test/installations/new"


def test_a_connected_installation_is_listed_with_its_repositories(client: TestClient) -> None:
    sign_in(client)
    (item,) = client.get("/installations").json()["items"]
    assert item["id"] == 9001
    assert item["account_login"] == "acme"
    assert item["account_type"] == "Organization"
    assert item["repository_count"] == 2
    assert item["suspended"] is False
    assert item["manage_url"] == "https://github.com/organizations/acme/settings/installations/9001"


def test_only_the_tokens_installations_are_listed(
    client: TestClient, github: FakeGitHubGateway
) -> None:
    github.repositories[9002] = [
        InstallationRepository(
            repo_id=7001, full_name="someone-else/secrets", default_branch="main", is_private=True
        )
    ]
    sign_in(client, installation_ids=[9002])
    sign_in(client, installation_ids=[9001])
    assert [i["id"] for i in client.get("/installations").json()["items"]] == [9001]


def test_an_uninstalled_installation_is_not_connected_and_its_repositories_are_hidden(
    client: TestClient, db: DbSession
) -> None:
    """Hidden, not deleted (D-102): a token issued before the uninstall still sees nothing of it."""
    sign_in(client)
    mark_installation_uninstalled(db, 9001)
    db.flush()

    assert client.get("/installations").json()["items"] == []
    assert client.get("/repositories").json()["items"] == []


def test_a_deselected_repository_is_hidden_and_not_counted(
    client: TestClient, db: DbSession
) -> None:
    sign_in(client)
    assert mark_repositories_removed(db, 9001, [5001]) == 1
    db.flush()

    names = [r["full_name"] for r in client.get("/repositories").json()["items"]]
    assert names == ["acme/internal-tools"]
    (item,) = client.get("/installations").json()["items"]
    assert item["repository_count"] == 1


def test_a_personal_installation_is_managed_from_the_users_own_settings(
    client: TestClient, github: FakeGitHubGateway, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codesheriff_api.github_gateway import InstallationAccount

    monkeypatch.setattr(
        github,
        "get_installation",
        lambda installation_id: InstallationAccount(
            installation_id=installation_id, account_login="octo-dev", account_type="User"
        ),
    )
    sign_in(client)
    (item,) = client.get("/installations").json()["items"]
    assert item["manage_url"] == "https://github.com/settings/installations/9001"
