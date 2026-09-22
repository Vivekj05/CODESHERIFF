"""Sign-in, session scoping and the repository list, against a real database and a fake GitHub.

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

The interesting assertions are the refusals: what a forged state does, what an unknown cookie does,
and what a session can see that belongs to an installation it was never granted.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from codesheriff_api.auth import NEXT_COOKIE, STATE_COOKIE
from codesheriff_api.github_gateway import GitHubIdentity, InstallationRepository
from codesheriff_storage import hash_session_token
from codesheriff_storage.models import Session as SessionRow
from codesheriff_storage.models import User

from .conftest import FakeGitHubGateway

pytestmark = pytest.mark.db


def stored_next_path(client: TestClient) -> str:
    """The `next` cookie as the server will read it back.

    A path contains `/`, which `http.cookies` quotes on the way out and unquotes on the way in. The
    cookie jar hands back the wire value, so the quotes are stripped here rather than pretended
    away — the state cookie is the one that must stay raw, and it does.
    """
    return client.cookies[NEXT_COOKIE].strip('"')


def start_login(client: TestClient, next_path: str = "/repositories") -> tuple[str, str]:
    """Drive `/auth/login` and return (state, the next path the server stored)."""
    response = client.get("/auth/login", params={"next": next_path})
    assert response.status_code == 307
    state = parse_qs(urlparse(response.headers["location"]).query)["state"][0]
    return state, stored_next_path(client)


def sign_in(client: TestClient, code: str = "good-code") -> None:
    """Complete a whole sign-in, leaving the session cookie on the client."""
    state, _ = start_login(client)
    response = client.get("/auth/callback", params={"code": code, "state": state})
    assert response.status_code == 303, response.text


def test_login_redirects_to_github_with_state_and_callback(client: TestClient) -> None:
    response = client.get("/auth/login")
    assert response.status_code == 307

    target = urlparse(response.headers["location"])
    query = parse_qs(target.query)
    assert target.netloc == "github.com"
    assert query["client_id"] == ["Iv1.testclientid"]
    assert query["redirect_uri"] == ["http://localhost:8000/auth/callback"]
    assert len(query["state"][0]) >= 20

    assert client.cookies[STATE_COOKIE] == query["state"][0]
    assert all("httponly" in header.lower() for header in response.headers.get_list("set-cookie"))


def test_login_does_not_reflect_an_offsite_next_path(client: TestClient) -> None:
    client.get("/auth/login", params={"next": "//evil.example/steal"})
    assert stored_next_path(client) == "/repositories"


def test_callback_completes_and_sets_an_httponly_session_cookie(
    client: TestClient, db: DbSession
) -> None:
    state, _ = start_login(client, next_path="/audits")
    response = client.get("/auth/callback", params={"code": "good-code", "state": state})

    assert response.status_code == 303
    assert response.headers["location"] == "http://localhost:3000/audits"

    set_cookie = response.headers["set-cookie"].lower()
    assert "httponly" in set_cookie
    assert "samesite=lax" in set_cookie

    user = db.execute(select(User)).scalar_one()
    assert (user.login, user.id) == ("octo-dev", 4242)
    assert user.last_login_at is not None


def test_the_session_token_is_never_stored(client: TestClient, db: DbSession) -> None:
    """The cookie holds the secret; the database holds only a hash of it (D-036)."""
    sign_in(client)
    token = client.cookies["codesheriff_session"]

    row = db.execute(select(SessionRow)).scalar_one()
    assert row.token_sha256 == hash_session_token(token)
    assert token not in str(row.token_sha256)


def test_forged_state_is_rejected(client: TestClient) -> None:
    start_login(client)
    response = client.get("/auth/callback", params={"code": "good-code", "state": "not-the-state"})
    assert response.status_code == 400
    assert "codesheriff_session" not in response.cookies


def test_callback_without_a_prior_login_is_rejected(client: TestClient) -> None:
    """No state cookie means this browser never started a flow — CSRF on login."""
    response = client.get("/auth/callback", params={"code": "good-code", "state": "anything"})
    assert response.status_code == 400


def test_github_refusing_the_code_is_a_bad_gateway_not_a_crash(client: TestClient) -> None:
    state, _ = start_login(client)
    response = client.get("/auth/callback", params={"code": "bad-code", "state": state})
    assert response.status_code == 502


def test_sign_in_syncs_installations_and_repositories(client: TestClient) -> None:
    sign_in(client)
    body = client.get("/repositories").json()
    assert [item["full_name"] for item in body["items"]] == [
        "acme/internal-tools",
        "acme/payments-api",
    ]


def test_one_broken_installation_does_not_fail_sign_in(
    client: TestClient, github: FakeGitHubGateway
) -> None:
    """A suspended or just-uninstalled installation is a normal state, not an auth failure."""
    github.identity = GitHubIdentity(
        github_id=4242,
        login="octo-dev",
        name="Octo Dev",
        avatar_url=None,
        installation_ids=[9001, 9999],
    )
    github.failing_installations = {9999}

    sign_in(client)

    body = client.get("/repositories").json()
    assert len(body["items"]) == 2


def test_session_endpoint_reports_the_signed_in_user(client: TestClient) -> None:
    sign_in(client)
    body = client.get("/auth/session").json()
    assert body["login"] == "octo-dev"
    assert body["installation_count"] == 1
    assert body["install_url"] == "https://github.com/apps/codesheriff-test/installations/new"


def test_every_protected_route_needs_a_session(client: TestClient) -> None:
    for method, path in (("GET", "/auth/session"), ("GET", "/repositories")):
        response = client.request(method, path)
        assert response.status_code == 401, f"{method} {path} answered {response.status_code}"


def test_an_unknown_cookie_is_not_a_session(client: TestClient) -> None:
    client.cookies.set("codesheriff_session", "definitely-not-a-real-token")
    assert client.get("/auth/session").status_code == 401


def test_logout_revokes_server_side(client: TestClient, db: DbSession) -> None:
    """Clearing a cookie only asks the browser to forget; a copy taken first must stop working."""
    sign_in(client)
    stolen = client.cookies["codesheriff_session"]

    assert client.post("/auth/logout").status_code == 204

    row = db.execute(select(SessionRow)).scalar_one()
    assert row.revoked_at is not None

    client.cookies.set("codesheriff_session", stolen)
    assert client.get("/auth/session").status_code == 401


def test_repositories_are_scoped_to_the_sessions_installations(
    client: TestClient, github: FakeGitHubGateway, db: DbSession
) -> None:
    """The core access check: rows exist, the session was never granted them, the API omits them."""
    github.repositories[9002] = [
        InstallationRepository(
            repo_id=7001,
            full_name="someone-else/secrets",
            default_branch="main",
            is_private=True,
        )
    ]
    # Sign in once as a user who CAN see 9002, so the rows land in the database.
    github.identity = GitHubIdentity(
        github_id=1, login="other", name=None, avatar_url=None, installation_ids=[9002]
    )
    sign_in(client)
    assert [i["full_name"] for i in client.get("/repositories").json()["items"]] == [
        "someone-else/secrets"
    ]

    # Now sign in as a user who cannot.
    client.cookies.clear()
    github.identity = GitHubIdentity(
        github_id=4242, login="octo-dev", name=None, avatar_url=None, installation_ids=[9001]
    )
    sign_in(client)

    names = [i["full_name"] for i in client.get("/repositories").json()["items"]]
    assert "someone-else/secrets" not in names
    assert names == ["acme/internal-tools", "acme/payments-api"]


def test_toggling_a_repository_outside_the_session_is_a_404(
    client: TestClient, github: FakeGitHubGateway
) -> None:
    github.repositories[9002] = [
        InstallationRepository(
            repo_id=7001, full_name="someone-else/secrets", default_branch="main", is_private=True
        )
    ]
    github.identity = GitHubIdentity(
        github_id=1, login="other", name=None, avatar_url=None, installation_ids=[9002]
    )
    sign_in(client)
    client.cookies.clear()

    github.identity = GitHubIdentity(
        github_id=4242, login="octo-dev", name=None, avatar_url=None, installation_ids=[9001]
    )
    sign_in(client)

    response = client.patch("/repositories/7001", json={"analysis_enabled": False})
    assert response.status_code == 404


def test_toggling_analysis_persists(client: TestClient) -> None:
    sign_in(client)
    assert client.patch("/repositories/5001", json={"analysis_enabled": False}).json() == {
        "id": 5001,
        "full_name": "acme/payments-api",
        "default_branch": "main",
        "is_private": True,
        "analysis_enabled": False,
    }
    listed = {
        i["full_name"]: i["analysis_enabled"] for i in client.get("/repositories").json()["items"]
    }
    assert listed["acme/payments-api"] is False


def test_a_resync_does_not_re_enable_analysis_somebody_turned_off(client: TestClient) -> None:
    """A routine sync from GitHub must not undo a user's choice."""
    sign_in(client)
    client.patch("/repositories/5001", json={"analysis_enabled": False})

    client.cookies.clear()
    sign_in(client)

    listed = {
        i["full_name"]: i["analysis_enabled"] for i in client.get("/repositories").json()["items"]
    }
    assert listed["acme/payments-api"] is False


def test_listing_pages_by_keyset_cursor(client: TestClient, github: FakeGitHubGateway) -> None:
    github.repositories[9001] = [
        InstallationRepository(
            repo_id=6000 + n,
            full_name=f"acme/repo-{n:02d}",
            default_branch="main",
            is_private=False,
        )
        for n in range(5)
    ]
    sign_in(client)

    first = client.get("/repositories", params={"limit": 2}).json()
    assert [i["full_name"] for i in first["items"]] == ["acme/repo-00", "acme/repo-01"]
    assert first["next_cursor"] == "acme/repo-01"

    second = client.get("/repositories", params={"limit": 2, "cursor": first["next_cursor"]}).json()
    assert [i["full_name"] for i in second["items"]] == ["acme/repo-02", "acme/repo-03"]

    last = client.get("/repositories", params={"limit": 2, "cursor": second["next_cursor"]}).json()
    assert [i["full_name"] for i in last["items"]] == ["acme/repo-04"]
    assert last["next_cursor"] is None


def test_install_callback_grants_nothing_and_re_derives(client: TestClient) -> None:
    """`installation_id` arrives in a URL the user controls, so it must not widen a session."""
    sign_in(client)
    before = client.get("/auth/session").json()["installation_count"]

    response = client.get(
        "/auth/install/callback", params={"installation_id": 9999, "setup_action": "install"}
    )

    assert response.status_code == 303
    assert response.headers["location"].endswith("/auth/login?next=/repositories")
    assert client.get("/auth/session").json()["installation_count"] == before
