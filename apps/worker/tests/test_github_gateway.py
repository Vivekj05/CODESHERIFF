"""The real `githubkit` gateway, driven against an httpx `MockTransport`.

`FakeGitHubGateway` keeps the task tests honest about *our* logic, but it cannot catch a wrong
endpoint or a response shape read incorrectly — and this gateway writes to other people's pull
requests, so the first time it meets GitHub is a bad time to find out. These tests exercise
`GitHubKitGateway` itself and assert on the requests it emits, with no socket involved.

No database, so they run in every suite, not only under `-m db`.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from githubkit_schemas.latest.models import IssueComment

from codesheriff_worker.config import WorkerConfig
from codesheriff_worker.github_gateway import GitHubError, GitHubKitGateway

from .payloads import payload_for

INSTALLATION_TOKEN_PATH = "/app/installations/9001/access_tokens"


@pytest.fixture
def config(tmp_path: Path) -> WorkerConfig:
    key = tmp_path / "app.pem"
    key.write_text(TEST_PRIVATE_KEY)
    return WorkerConfig(
        _env_file=None,  # type: ignore[call-arg]
        GITHUB_APP_ID="123456",
        GITHUB_APP_PRIVATE_KEY_PATH=str(key),
    )


def comment_payload(comment_id: int) -> dict[str, object]:
    """Generated from githubkit's own schema, so it stays valid as that schema moves.

    githubkit validates every response body. A hand-written fixture with only the field the gateway
    reads fails validation before the gateway ever sees it.
    """
    return payload_for(IssueComment, id=comment_id, body="…")


def test_a_new_comment_is_posted_to_the_issues_endpoint(config: WorkerConfig) -> None:
    """Pull request comments are issue comments. The review-comments endpoint is a different
    thing — it anchors to a line — and D-034 rejects that deliberately."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return httpx.Response(
                201, json={"token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z"}
            )
        if request.url.path == "/repos/acme/payments-api/issues/7/comments":
            return httpx.Response(201, json=comment_payload(5101))
        raise AssertionError(f"unexpected request to {request.url}")

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))
    comment_id = gateway.post_or_update_comment(9001, "acme/payments-api", 7, "hello")

    assert comment_id == 5101
    posted = next(r for r in seen if r.url.path.endswith("/issues/7/comments"))
    assert posted.method == "POST"
    assert b"hello" in posted.content
    # Acting as the installation, never as the App and never as a user.
    assert "ghs_installation" in posted.headers["authorization"]


def test_a_known_comment_is_edited_in_place(config: WorkerConfig) -> None:
    """D-034: one summary comment per pull request, edited on each push."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return httpx.Response(
                201, json={"token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z"}
            )
        if request.url.path == "/repos/acme/payments-api/issues/comments/5101":
            return httpx.Response(200, json=comment_payload(5101))
        raise AssertionError(f"unexpected request to {request.url}")

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))
    comment_id = gateway.post_or_update_comment(
        9001, "acme/payments-api", 7, "revised", comment_id=5101
    )

    assert comment_id == 5101
    assert not any(r.url.path.endswith("/issues/7/comments") for r in seen)
    edited = next(r for r in seen if r.url.path.endswith("/issues/comments/5101"))
    assert edited.method == "PATCH"


def test_a_deleted_comment_falls_back_to_posting_a_new_one(config: WorkerConfig) -> None:
    """Somebody deleted the bot's comment. Refusing would mean the audit produced nothing."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return httpx.Response(
                201, json={"token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z"}
            )
        if request.url.path == "/repos/acme/payments-api/issues/comments/5101":
            return httpx.Response(404, json={"message": "Not Found"})
        if request.url.path == "/repos/acme/payments-api/issues/7/comments":
            return httpx.Response(201, json=comment_payload(5202))
        raise AssertionError(f"unexpected request to {request.url}")

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))
    comment_id = gateway.post_or_update_comment(
        9001, "acme/payments-api", 7, "body", comment_id=5101
    )

    assert comment_id == 5202


def test_a_refusal_raises_github_error_without_leaking_the_body(config: WorkerConfig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return httpx.Response(
                201, json={"token": "ghs_secret_value", "expires_at": "2099-01-01T00:00:00Z"}
            )
        return httpx.Response(403, json={"message": "Resource not accessible by integration"})

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))

    with pytest.raises(GitHubError) as caught:
        gateway.post_or_update_comment(9001, "acme/payments-api", 7, "body")

    # An exception string ends up in logs. It names the failure class and nothing else.
    assert "ghs_secret_value" not in str(caught.value)
    assert "acme/payments-api#7" in str(caught.value)


def test_a_malformed_repository_name_is_refused_before_any_call(config: WorkerConfig) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"should not have called {request.url}")

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))

    with pytest.raises(GitHubError):
        gateway.post_or_update_comment(9001, "payments-api", 7, "body")


# A throwaway 2048-bit RSA key, generated for the test suite and used nowhere else. It exists so
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
