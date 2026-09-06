"""The real `githubkit` gateway, driven against an httpx `MockTransport`.

`FakeGitHubGateway` keeps the task tests honest about *our* logic, but it cannot catch a wrong
endpoint or a response shape read incorrectly — and this gateway writes to other people's pull
requests, so the first time it meets GitHub is a bad time to find out. These tests exercise
`GitHubKitGateway` itself and assert on the requests it emits, with no socket involved.

No database, so they run in every suite, not only under `-m db`.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
from githubkit_schemas.latest.models import DiffEntry, IssueComment

from codesheriff_worker.config import WorkerConfig
from codesheriff_worker.github_gateway import (
    MAX_BLOB_BYTES,
    PER_PAGE,
    GitHubError,
    GitHubKitGateway,
)

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
    """Pull request comments are issue comments.

    The review-comments endpoint is a different thing — it anchors to a run of lines on a commit —
    and D-034 rejects it *for the summary comment*, which has to survive being edited in place
    across pushes. Chapter 17 uses it for suggested repairs, where anchoring is the point; those
    are never edited, and the tests for them are at the bottom of this file."""
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


def token_response() -> httpx.Response:
    return httpx.Response(
        201, json={"token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z"}
    )


def diff_entry(filename: str, status: str = "modified", **extra: object) -> dict[str, object]:
    return payload_for(DiffEntry, filename=filename, status=status, **extra)


# -- listing the files of a pull request ------------------------------------------------------


def test_the_file_list_is_paged_to_the_end(config: WorkerConfig) -> None:
    """GitHub caps a page at 100 and reports no usable total, so a short page is the only end
    marker. Stopping after one page would analyse the first hundred files of a large pull request
    and call the rest clean."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return token_response()
        if request.url.path == "/repos/acme/payments-api/pulls/7/files":
            if request.url.params["page"] == "1":
                return httpx.Response(
                    200, json=[diff_entry(f"pkg/mod{i}.py") for i in range(PER_PAGE)]
                )
            return httpx.Response(200, json=[diff_entry("pkg/last.py", status="added")])
        raise AssertionError(f"unexpected request to {request.url}")

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))
    files = gateway.list_pull_request_files(9001, "acme/payments-api", 7)

    assert len(files) == PER_PAGE + 1
    assert (files[-1].path, files[-1].status) == ("pkg/last.py", "added")
    assert [r.url.params["page"] for r in seen if "files" in r.url.path] == ["1", "2"]


def test_a_rename_carries_the_path_its_pre_image_lives_at(config: WorkerConfig) -> None:
    """Reading the new path on the base commit would 404, the file would look new, and the audit
    would report a rename as a rewrite of every line."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return token_response()
        return httpx.Response(
            200,
            json=[diff_entry("new/name.py", status="renamed", previous_filename="old/name.py")],
        )

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))

    assert gateway.list_pull_request_files(9001, "acme/payments-api", 7)[0].previous_path == (
        "old/name.py"
    )


def test_the_file_list_never_carries_the_patch(config: WorkerConfig) -> None:
    """GitHub omits `patch` on a large diff, and the superseded parser both reconstructed source
    from it and skipped the files that lacked it (AUDIT.md 4.1, 4.2). There is no field on
    `PullRequestFile` for a later caller to reach for."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return token_response()
        return httpx.Response(200, json=[diff_entry("a.py", patch="@@ -1 +1 @@")])

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))
    entry = gateway.list_pull_request_files(9001, "acme/payments-api", 7)[0]

    assert not hasattr(entry, "patch")


# -- fetching one blob ------------------------------------------------------------------------

CONTENTS_PATH = "/repos/acme/payments-api/contents/pkg/mod.py"


def serving(body: bytes, status: int = 200) -> Callable[[httpx.Request], httpx.Response]:
    """A transport that answers the contents endpoint with `body`, or fails with `status`."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return token_response()
        if request.url.path == CONTENTS_PATH:
            if status != 200:
                return httpx.Response(status, json={"message": "Refused"})
            return httpx.Response(200, content=body)
        raise AssertionError(f"unexpected request to {request.url}")

    return handler


def fetching(
    config: WorkerConfig,
    body: bytes,
    status: int = 200,
    ref: str = "h" * 40,
) -> str | None:
    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(serving(body, status)))
    return gateway.get_file_at_ref(9001, "acme/payments-api", "pkg/mod.py", ref)


def test_a_blob_is_fetched_raw_at_the_requested_ref(config: WorkerConfig) -> None:
    """The raw media type rather than the default JSON representation, which base64-encodes the
    body and inflates a source file by a third for metadata nothing here reads."""
    seen: list[httpx.Request] = []
    inner = serving(b"def f():\n    return 1\n")

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return inner(request)

    gateway = GitHubKitGateway(config, transport=httpx.MockTransport(handler))
    source = gateway.get_file_at_ref(9001, "acme/payments-api", "pkg/mod.py", "h" * 40)

    assert source == "def f():\n    return 1\n"
    fetched = next(r for r in seen if r.url.path == CONTENTS_PATH)
    assert fetched.url.params["ref"] == "h" * 40
    assert fetched.headers["accept"] == "application/vnd.github.raw"


def test_a_file_absent_at_that_ref_is_none_rather_than_an_error(config: WorkerConfig) -> None:
    """Ordinary, not exceptional: an added file has no image on the base commit."""
    assert fetching(config, b"", status=404, ref="b" * 40) is None


def test_a_blob_over_the_budget_is_not_analysed(config: WorkerConfig) -> None:
    """A cap on the fetch, which is a different thing from truncating a unit: the file is skipped
    whole, so no agent is ever handed part of one."""
    assert fetching(config, b"x" * (MAX_BLOB_BYTES + 1)) is None


def test_a_blob_at_the_budget_is_analysed(config: WorkerConfig) -> None:
    assert fetching(config, b"x" * MAX_BLOB_BYTES) is not None


def test_a_binary_blob_is_skipped_rather_than_mangled(config: WorkerConfig) -> None:
    """Decoding with errors="replace" would hand an agent a file of substitution characters and
    let it report findings about bytes that were never there."""
    assert fetching(config, b"\x89PNG\r\n\x1a\n\xff\xfe") is None


def test_an_unexpected_refusal_raises_rather_than_reading_as_a_new_file(
    config: WorkerConfig,
) -> None:
    """A 403 answered with None would make an unreadable file indistinguishable from an added
    one, and every line of it would then be reported as changed."""
    with pytest.raises(GitHubError):
        fetching(config, b"", status=403)


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


# ---------------------------------------------------------------------------
# Suggested repairs (Chapter 17). A different endpoint from the summary comment, and a different
# lifecycle: anchored to a commit, and never edited in place (D-095).
# ---------------------------------------------------------------------------

REVIEW_COMMENTS_PATH = "/repos/acme/payments-api/pulls/7/comments"


def review_transport(seen: list[httpx.Request], status: int = 201) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == INSTALLATION_TOKEN_PATH:
            return httpx.Response(
                201, json={"token": "ghs_installation", "expires_at": "2099-01-01T00:00:00Z"}
            )
        if request.url.path == REVIEW_COMMENTS_PATH:
            return httpx.Response(status, json={"id": 77001} if status < 300 else {"message": "x"})
        raise AssertionError(f"unexpected request to {request.url}")

    return httpx.MockTransport(handler)


def sent_body(seen: list[httpx.Request]) -> dict[str, object]:
    import json

    request = next(r for r in seen if r.url.path == REVIEW_COMMENTS_PATH)
    body = json.loads(request.content)
    assert isinstance(body, dict)
    return body


def test_a_multi_line_suggestion_carries_both_ends_of_the_span(config: WorkerConfig) -> None:
    seen: list[httpx.Request] = []
    gateway = GitHubKitGateway(config, transport=review_transport(seen))

    comment_id = gateway.post_review_comment(
        installation_id=9001,
        repo_full_name="acme/payments-api",
        pr_number=7,
        commit_sha="b" * 40,
        path="app/db.py",
        start_line=11,
        line=12,
        body="a suggestion block",
    )

    assert comment_id == 77001
    body = sent_body(seen)
    assert body["commit_id"] == "b" * 40
    assert body["path"] == "app/db.py"
    assert (body["start_line"], body["line"]) == (11, 12)
    assert body["side"] == body["start_side"] == "RIGHT"


def test_a_single_line_suggestion_sends_no_start_line(config: WorkerConfig) -> None:
    """GitHub rejects `start_line == line` rather than reading it as a one-line span.

    Sending it unconditionally would fail every single-line repair — which is the most common
    shape a repair takes.
    """
    seen: list[httpx.Request] = []
    gateway = GitHubKitGateway(config, transport=review_transport(seen))

    gateway.post_review_comment(
        installation_id=9001,
        repo_full_name="acme/payments-api",
        pr_number=7,
        commit_sha="b" * 40,
        path="app/db.py",
        start_line=11,
        line=11,
        body="…",
    )

    body = sent_body(seen)
    assert "start_line" not in body
    assert "start_side" not in body
    assert body["line"] == 11


def test_a_rejected_anchor_becomes_a_github_error_naming_the_lines(
    config: WorkerConfig,
) -> None:
    """422 is the ordinary failure, and it means the anchor was not in the diff.

    The patcher already refuses to publish outside `changed_lines` (D-095), so this is a defect
    report rather than an expected path — and the message has to say enough to file one.
    """
    seen: list[httpx.Request] = []
    gateway = GitHubKitGateway(config, transport=review_transport(seen, status=422))

    with pytest.raises(GitHubError, match="lines 11-12"):
        gateway.post_review_comment(
            installation_id=9001,
            repo_full_name="acme/payments-api",
            pr_number=7,
            commit_sha="b" * 40,
            path="app/db.py",
            start_line=11,
            line=12,
            body="…",
        )
