"""Token verification, session scoping and the repository list (D-101).

`pytest -m db` with `CODESHERIFF_TEST_DB` set; skipped otherwise (D-029).

Sign-in runs in the dashboard under Better Auth; the API only verifies the JWT it is handed. So the
interesting assertions are the refusals: a token signed by the wrong key, with `alg: none`, from
another issuer, expired, or claiming installations in the wrong shape; and what a valid token can
see that belongs to an installation it was never granted.
"""

from __future__ import annotations

from datetime import timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from codesheriff_api.github_gateway import InstallationRepository

from .conftest import FakeGitHubGateway, mint_token, sign_in

pytestmark = pytest.mark.db


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_a_valid_token_is_a_session(client: TestClient) -> None:
    response = client.get("/auth/session", headers=bearer(mint_token()))
    assert response.status_code == 200
    body = response.json()
    assert body["login"] == "octo-dev"
    assert body["installation_count"] == 1
    assert body["install_url"] == "https://github.com/apps/codesheriff-test/installations/new"


def test_every_protected_route_needs_a_token(client: TestClient) -> None:
    for path in ("/auth/session", "/repositories", "/audits", "/stats/overview", "/calibration"):
        response = client.get(path)
        assert response.status_code == 401, f"{path} answered {response.status_code}"
        assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(mint_token(key=Ed25519PrivateKey.generate()), id="signed-by-another-key"),
        pytest.param(mint_token(issuer="https://evil.example"), id="wrong-issuer"),
        pytest.param(mint_token(audience="https://evil.example"), id="wrong-audience"),
        pytest.param(mint_token(expires_in=timedelta(seconds=-5)), id="expired"),
        pytest.param(mint_token(installation_ids="9001"), id="installations-not-a-list"),  # type: ignore[arg-type]
        pytest.param(mint_token(installation_ids=["9001"]), id="installations-as-strings"),  # type: ignore[list-item]
        pytest.param(mint_token(login=""), id="no-login"),
        pytest.param("not-a-jwt", id="garbage"),
    ],
)
def test_a_bad_token_is_not_a_session(client: TestClient, token: str) -> None:
    assert client.get("/auth/session", headers=bearer(token)).status_code == 401


def test_an_unsigned_token_is_refused(client: TestClient) -> None:
    """`alg: none` must never be accepted, whatever the header claims."""
    token = jwt.encode(
        {"sub": "x", "login": "x", "installation_ids": [9001]}, key=None, algorithm="none"
    )
    assert client.get("/auth/session", headers=bearer(token)).status_code == 401


def test_a_token_with_another_algorithm_is_refused(client: TestClient) -> None:
    """Only EdDSA is accepted; a token cannot choose a symmetric algorithm for itself."""
    token = mint_token(key="a-shared-secret-long-enough-for-hs256!", algorithm="HS256")  # type: ignore[arg-type]
    assert client.get("/auth/session", headers=bearer(token)).status_code == 401


def test_a_cookie_is_not_a_session_any_more(client: TestClient) -> None:
    client.cookies.set("codesheriff_session", "anything")
    assert client.get("/auth/session").status_code == 401


def test_the_session_syncs_installations_and_repositories(client: TestClient) -> None:
    sign_in(client)
    body = client.get("/repositories").json()
    assert [item["full_name"] for item in body["items"]] == [
        "acme/internal-tools",
        "acme/payments-api",
    ]


def test_known_installations_are_not_read_again(
    client: TestClient, github: FakeGitHubGateway
) -> None:
    """The webhooks keep known installations current; re-reading them would spend rate limit."""
    sign_in(client)
    sign_in(client)
    assert github.installations_read == [9001]


def test_one_broken_installation_does_not_fail_the_session(
    client: TestClient, github: FakeGitHubGateway
) -> None:
    """A suspended or just-uninstalled installation is a normal state, not an auth failure."""
    github.failing_installations = {9999}
    sign_in(client, installation_ids=[9001, 9999])
    assert len(client.get("/repositories").json()["items"]) == 2


def test_an_empty_installation_list_sees_nothing(client: TestClient) -> None:
    sign_in(client, installation_ids=[9001])
    sign_in(client, installation_ids=[])
    assert client.get("/repositories").json()["items"] == []


def test_repositories_are_scoped_to_the_tokens_installations(
    client: TestClient, github: FakeGitHubGateway
) -> None:
    """The core access check: rows exist, this token was never granted them, the API omits them."""
    github.repositories[9002] = [
        InstallationRepository(
            repo_id=7001, full_name="someone-else/secrets", default_branch="main", is_private=True
        )
    ]
    # Somebody who CAN see 9002 signs in, so its rows land in the database.
    sign_in(client, installation_ids=[9002])
    assert [i["full_name"] for i in client.get("/repositories").json()["items"]] == [
        "someone-else/secrets"
    ]

    # Now a token that cannot.
    sign_in(client, installation_ids=[9001])
    names = [i["full_name"] for i in client.get("/repositories").json()["items"]]
    assert "someone-else/secrets" not in names
    assert names == ["acme/internal-tools", "acme/payments-api"]


def test_toggling_a_repository_outside_the_token_is_a_404(
    client: TestClient, github: FakeGitHubGateway
) -> None:
    github.repositories[9002] = [
        InstallationRepository(
            repo_id=7001, full_name="someone-else/secrets", default_branch="main", is_private=True
        )
    ]
    sign_in(client, installation_ids=[9002])
    sign_in(client, installation_ids=[9001])

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


def test_signing_in_again_does_not_re_enable_analysis(client: TestClient) -> None:
    """A routine sign-in must not undo a user's choice."""
    sign_in(client)
    client.patch("/repositories/5001", json={"analysis_enabled": False})
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
    """`installation_id` arrives in a URL the user controls, so it must not widen what is seen."""
    sign_in(client)
    before = client.get("/auth/session").json()["installation_count"]

    response = client.get(
        "/auth/install/callback", params={"installation_id": 9999, "setup_action": "install"}
    )

    assert response.status_code == 303
    assert (
        response.headers["location"] == "http://localhost:3000/sign-in?next=/github-app&refresh=1"
    )
    assert client.get("/auth/session").json()["installation_count"] == before


def test_the_old_oauth_callback_re_derives_and_exchanges_nothing(
    client: TestClient, github: FakeGitHubGateway
) -> None:
    """A stale App setting still lands here after an install; the code in the URL is never used."""
    response = client.get(
        "/auth/callback",
        params={"code": "abc", "installation_id": 9999, "setup_action": "update"},
    )
    assert response.status_code == 303
    assert (
        response.headers["location"] == "http://localhost:3000/sign-in?next=/github-app&refresh=1"
    )
    assert github.installations_read == []
