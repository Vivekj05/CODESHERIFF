"""The real `githubkit` gateway, driven against an httpx `MockTransport`.

`FakeGitHubGateway` keeps the route tests honest about *our* logic, but it cannot catch a wrong
endpoint, a missing `redirect_uri`, or a response shape we read incorrectly — the three things most
likely to be wrong the first time this meets GitHub. These tests exercise `GitHubKitGateway` itself
and assert on the requests it actually emits, with no socket involved.

Response bodies come from `payloads.payload_for`, which generates them from githubkit's own schemas,
so they stay valid as those schemas change.

No database, so these run in every suite, not only under `-m db`.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qs

import httpx
import pytest
from githubkit_schemas.latest.models import Installation, PrivateUser, Repository, SimpleUser

from codesheriff_api.config import ApiConfig
from codesheriff_api.github_gateway import GitHubError, GitHubKitGateway

from .payloads import payload_for


@pytest.fixture
def config() -> ApiConfig:
    return ApiConfig(
        _env_file=None,  # type: ignore[call-arg]
        GITHUB_APP_ID="123456",
        GITHUB_APP_CLIENT_ID="Iv1.testclientid",
        GITHUB_APP_CLIENT_SECRET="test-client-secret",
        API_PUBLIC_URL="http://localhost:8000",
    )


def exchange_body(request: httpx.Request) -> dict[str, str]:
    """The token-exchange parameters, however githubkit chose to encode them.

    It sends JSON today and the endpoint also accepts form encoding; the assertions are about the
    parameters, not the wire format.
    """
    raw = request.content.decode()
    if request.headers.get("content-type", "").startswith("application/json"):
        return {str(k): str(v) for k, v in json.loads(raw).items()}
    return {key: values[0] for key, values in parse_qs(raw).items()}


def user_payload(user_id: int = 4242, login: str = "octo-dev") -> dict[str, object]:
    return payload_for(
        PrivateUser, id=user_id, login=login, name="Octo Dev", avatar_url="https://a/"
    )


def installation_payload(installation_id: int) -> dict[str, object]:
    return payload_for(
        Installation,
        id=installation_id,
        account=payload_for(SimpleUser, login="acme", type="Organization"),
    )


def repository_payload(
    repo_id: int, full_name: str, branch: str, private: bool
) -> dict[str, object]:
    return payload_for(
        Repository, id=repo_id, full_name=full_name, default_branch=branch, private=private
    )


def test_sign_in_exchanges_the_code_then_reads_identity_and_installations(
    config: ApiConfig,
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        path = request.url.path

        if path == "/login/oauth/access_token":
            return httpx.Response(
                200,
                json={"access_token": "gho_exchanged", "token_type": "bearer", "scope": ""},
            )
        if path == "/user":
            return httpx.Response(200, json=user_payload())
        if path == "/user/installations":
            return httpx.Response(
                200,
                json={
                    "total_count": 2,
                    "installations": [installation_payload(9001), installation_payload(9002)],
                },
            )
        raise AssertionError(f"unexpected request to {request.url}")

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))
    identity = gateway.sign_in("the-code")

    assert identity.github_id == 4242
    assert identity.login == "octo-dev"
    assert identity.installation_ids == [9001, 9002]

    exchange = next(r for r in seen if r.url.path == "/login/oauth/access_token")
    body = exchange_body(exchange)
    assert body["client_id"] == "Iv1.testclientid"
    assert body["client_secret"] == "test-client-secret"
    assert body["code"] == "the-code"
    # The redirect_uri must match the App's registered callback exactly, or GitHub rejects the
    # exchange with an error that says nothing useful.
    assert body["redirect_uri"] == "http://localhost:8000/auth/callback"

    # The token from the exchange is what the subsequent reads authenticate with, and it never
    # leaves the gateway.
    user_request = next(r for r in seen if r.url.path == "/user")
    assert "gho_exchanged" in user_request.headers["authorization"]


def test_a_rejected_code_raises_github_error_without_leaking_the_body(config: ApiConfig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401, json={"error": "bad_verification_code", "client_secret": "test-client-secret"}
        )

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))

    with pytest.raises(GitHubError) as caught:
        gateway.sign_in("stale-code")

    # The message names the failure class only. GitHub echoes request parameters in some error
    # bodies, and an exception string ends up in logs.
    assert "test-client-secret" not in str(caught.value)
    assert "sign-in failed" in str(caught.value)


def test_installation_repositories_follow_pagination(config: ApiConfig, tmp_path: Path) -> None:
    key = tmp_path / "app.pem"
    key.write_text(TEST_PRIVATE_KEY)
    config = config.model_copy(update={"github_app_private_key_path": str(key)})

    first_page = [
        repository_payload(6000 + n, f"acme/repo-{n:03d}", "main", False) for n in range(100)
    ]
    second_page = [repository_payload(7000, "acme/last", "trunk", True)]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/app/installations/9001/access_tokens":
            return httpx.Response(
                201, json={"token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z"}
            )
        if request.url.path == "/installation/repositories":
            page = request.url.params.get("page", "1")
            repositories = first_page if page == "1" else second_page
            return httpx.Response(200, json={"total_count": 101, "repositories": repositories})
        raise AssertionError(f"unexpected request to {request.url}")

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))
    repositories = gateway.list_installation_repositories(9001)

    # 101, not 100: a full page must be followed by another request, and a short page ends it.
    assert len(repositories) == 101
    assert repositories[-1].full_name == "acme/last"
    assert repositories[-1].default_branch == "trunk"
    assert repositories[-1].is_private is True


# A throwaway 2048-bit RSA key, generated for this test file and used nowhere else. It exists so
# githubkit can sign an App JWT locally; it authenticates nothing.
TEST_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAt5VC8MaAl5GKfkpdejs/c1rUfgcfOxexK9740kuEscNcQnDh
1HemIKLR6zzrrKMIl9GHVXhFCBdROQc4EstBsxxMQNYat3pDbt/DONQNRw+6w8DY
9QoNAWg9Heui7TMG8Oa1+m6669ywUL/30XvaTMLNg5aAH3IXemAsRZl3D4LLcM6w
EBWtTAE83RHXeWrShV4X2fY1RDih782/bWLJ4G22ZMNLoCFhOzS3y9rrk4UtJe3r
6ihs+HfXSw9WnNu3AeCuaGaxr/953xQCCEKpph3NKEkCp1aV7nNzHGACIiqUiPrH
HMqUYJcGrs6NJUwDjVqNTjOMla9GBLMzDSTRTQIDAQABAoIBAAvEwogPXZZ50sRC
TahEjI5/S+BxYe/mlqm+jzph83V21d7/gAagDfMJJQZcvynvwKEE4lVZEqnQXtlW
TGKuC33pKj08zHUnHhQJPalStLAxwrICVpYsyQUmUsasgKMOkpsWWyOc/hgZK2dd
ywvvkeC6WzTcjMWXSYiDiksC6cZBayzoDzN6ELipGxuNNBgxnlY+6N5NPeLIwlbo
Djo4rNz0LdDr3UMQitEuO7yaurKzjg/2kaBDizl7QYul/0wOlMQRsTkQ/RyGQNHc
8Tz4ifnZQiyptBvtezRSwJJbAnrhypKYm9ZZuYZFAD4hENs0p9njqcfah/Mut/zI
mV4QVlkCgYEA35IDJ4kYe4kLTRuxBnPxw5ND0xv7iwrEPedhq9ZM84aoj6IRENta
gQFWO3MX3pysQnmTIGn5ZkCJ9fgwhesG9USM3WPl4JVcS0IrWpMTzMhs2xuXE85T
um56edg0TcEZK/fheKhJqbIsidqgjlATZAYD+4FwxS7xcDxtfjfT/NUCgYEA0jZf
rFLvWajkMDbXKDl7hjuW6vU1l5eavcdpZwm5ScxHOsV1LXGRXhpFh9PV/3yc8PqW
FBlNFTBWIxPcnBMa06UjmYVtWkv0620DhRyBwHZVGdgtWp39p5xudhlIhXN/0vcA
FXA4G6CJYWpsumcFV/GD5O2pXbaOHPvc84Jq3pkCgYB2L8T1IHdNzvunbo0doStc
PTxsnG1UaoOlSe0LHwWc80GmdIFbDOqCKgfA863Zo684kPZi+0K5eEK2Qda85KrP
+8YPvyCloa+hpUAv6HJeHlHVXnd2I+uFMaQTR2UW+Y5p/Oc3lpciWytKUMXxlYk6
pidyzFGmG5PMxlUHlVG+ZQKBgAa+A7eNOWwQxLDfMWty3Iljo+WJU9y22hm4KaNK
Zoz9ZlN2PdnlSJpSEWTX4Ic/QfFguCuQ3C4PzNN3MZ435qZfJ5Mm+mjpAsQCTRiZ
33eC1BvuGRZM9vPHSquzB+Zv2+uyTGhjnwkTzxQ2y6H25+74KhjPnp0I2+oGEgIl
brQRAoGBAN6eK5yRfDNjHoSZcL5o1EH+l5cPC2uEXcMObbB/00cYMf0PsjQVReGG
l/2L1UTy5DfAQI7LcYFYuWE8pnib5Laa0gDVoW91OuJnq6vqHjjE8F/s5veae3M0
04lR8xfbpkpmm2uMD8IDXZVAhgVZJ61UA6KjFOVrhKL6uWTiznsD
-----END RSA PRIVATE KEY-----
"""
