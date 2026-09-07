"""Every GitHub call the worker makes, behind one Protocol.

A separate gateway from the API's, and not by oversight (D-042). The two have disjoint methods and
disjoint authentication: the API acts as a *user* through OAuth to answer "what may this person
see", while the worker acts as an *installation* to read a diff and write a comment. Merging them
would produce one interface whose every implementation had to satisfy both, and one process holding
both kinds of credential.

**Tests must never make live API calls** (CLAUDE.md). Substituting at this interface — rather than
at the HTTP layer — means the task runs its real code path against a fake that a changed signature
would break, instead of against a mocked response that a misspelled endpoint would still satisfy.

Synchronous, matching D-028. Celery is synchronous and owns the pipeline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from githubkit import AppAuthStrategy, BaseAuthStrategy, GitHub
from githubkit.exception import RequestFailed

from codesheriff_worker.config import WorkerConfig

logger = logging.getLogger(__name__)

PER_PAGE = 100
"""GitHub's maximum page size on every endpoint this gateway pages through."""

MAX_FILE_PAGES = 30
"""3,000 files, which is where GitHub stops listing them anyway. A bound rather than `while True`:
a paging loop with no ceiling turns one malformed response into a worker that never returns."""

MAX_BLOB_BYTES = 1_000_000
"""Largest file this worker will pull into memory to analyse.

A cap on the *fetch*, which is a different thing from truncating a unit. A file over the budget is
never fetched, so no agent is handed a partial file and no evidence is produced from one; the file
is recorded as skipped instead (`SkipReason.CONTENT_UNAVAILABLE`). Truncating source and analysing
what fits is what CLAUDE.md forbids, and it is forbidden precisely because a confident finding
drawn from half a file corrupts calibration without ever looking wrong.

One million bytes rather than GitHub's own 1 MiB Contents API limit, so the boundary is ours and
does not move when theirs does.
"""


class GitHubError(RuntimeError):
    """GitHub refused or could not answer. Carries no token material."""


@dataclass(frozen=True)
class PullRequestFile:
    """One entry of a pull request's file list.

    Deliberately *not* carrying `patch`. GitHub omits it for large diffs, and the previous parser
    both reconstructed source from it and skipped the files that lacked it (`AUDIT.md` 4.1, 4.2).
    Extraction diffs the two fetched blobs instead, so there is no field here for a caller to be
    tempted by and no branch that behaves differently when GitHub declines to send one.
    """

    path: str
    status: str
    previous_path: str | None = None
    """Set on a rename. The pre-image lives at this path on the base commit, not at `path`."""


class GitHubGateway(Protocol):
    """What the pipeline asks of GitHub."""

    def list_pull_request_files(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
    ) -> list[PullRequestFile]:
        """Every file the pull request touches, paginated to the end."""
        ...

    def get_file_at_ref(
        self,
        installation_id: int,
        repo_full_name: str,
        path: str,
        ref: str,
    ) -> str | None:
        """The file's text at one commit, or None if it is not there or not analysable text.

        None covers three ordinary cases that are not errors: the file does not exist at that ref
        (an added file has no base image), it is over `MAX_BLOB_BYTES`, or it is not valid UTF-8.
        Anything else raises, because a fetch that failed for an unknown reason must not read as
        "this file is new".
        """
        ...

    def post_or_update_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        body: str,
        comment_id: int | None = None,
    ) -> int:
        """Write the audit's one summary comment, and return its id.

        `comment_id` is the comment a previous audit of this pull request posted. Passing it edits
        that comment in place rather than adding another, which is the whole of D-034: a developer
        who pushes six times gets one comment that changes, not six that accumulate.
        """
        ...

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
        """Post one review comment anchored to a run of lines, and return its id.

        This is how a suggested change is delivered: the body carries a fenced `suggestion` block,
        and GitHub renders a button that applies it to `path` between `start_line` and `line` on
        `commit_sha`. Nothing is committed by posting it — §2 makes patches suggestions only, and a
        suggestion is applied by the person reviewing or not at all.

        **Never edited in place, unlike the summary comment.** A review comment is bound to a
        commit; the next push produces a new head SHA, a new anchor and a new comment, and GitHub
        marks the previous one outdated. Editing the old one would leave a suggestion pointing at
        code that has moved (D-095).

        `path` reaches GitHub as an API field and is never interpolated into the body, which is
        what keeps D-050 intact — the rendered text still names no file.
        """
        ...


class GitHubKitGateway:
    """The real implementation, on `githubkit`.

    `transport` exists for tests that want to drive this class itself rather than substitute a
    fake — an httpx `MockTransport` keeps even those offline.
    """

    def __init__(self, config: WorkerConfig, transport: httpx.BaseTransport | None = None) -> None:
        self._config = config
        self._transport = transport

    def _client(self, installation_id: int) -> GitHub[Any]:
        app = self._config.require_github_app()
        auth: BaseAuthStrategy = AppAuthStrategy(app.app_id, app.private_key).as_installation(
            installation_id
        )
        return GitHub(
            auth,
            base_url=self._config.github_api_base,
            transport=self._transport,
            user_agent="CodeSheriff",
        )

    @staticmethod
    def _split(repo_full_name: str) -> tuple[str, str]:
        owner, _, repo = repo_full_name.partition("/")
        if not owner or not repo:
            raise GitHubError(f"Not a repository full name: {repo_full_name!r}")
        return owner, repo

    def list_pull_request_files(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
    ) -> list[PullRequestFile]:
        owner, repo = self._split(repo_full_name)
        try:
            with self._client(installation_id) as github:
                files: list[PullRequestFile] = []
                for page in range(1, MAX_FILE_PAGES + 1):
                    batch = github.rest.pulls.list_files(
                        owner, repo, pr_number, per_page=PER_PAGE, page=page
                    ).parsed_data
                    files.extend(
                        PullRequestFile(
                            path=str(entry.filename),
                            status=str(entry.status),
                            previous_path=(
                                str(entry.previous_filename) if entry.previous_filename else None
                            ),
                        )
                        for entry in batch
                    )
                    # Stop on a short page. GitHub caps this endpoint at 3000 files and offers no
                    # total to compare against, so the page length is the only end marker.
                    if len(batch) < PER_PAGE:
                        return files
                logger.warning(
                    "Stopped listing files for %s#%s at %s pages; the pull request is larger than "
                    "this worker will enumerate",
                    repo_full_name,
                    pr_number,
                    MAX_FILE_PAGES,
                )
                return files
        except GitHubError:
            raise
        except Exception as exc:
            raise GitHubError(
                f"Could not list files of {repo_full_name}#{pr_number}: {type(exc).__name__}"
            ) from exc

    def get_file_at_ref(
        self,
        installation_id: int,
        repo_full_name: str,
        path: str,
        ref: str,
    ) -> str | None:
        """Fetch one blob as raw bytes.

        The raw media type rather than the default JSON representation, which base64-encodes the
        body and inflates a source file by a third for no gain — nothing here reads the metadata
        that representation wraps it in.

        `MAX_BLOB_BYTES` is applied to the body once it has arrived. Enforcing it before transfer
        would mean a metadata request per file, doubling the API cost of every audit against a
        5,000/hour budget, and the transfer is already bounded by GitHub's own ceiling. What the
        cap guarantees is the part that matters: an oversized file is never *analysed*, so no
        agent ever produces evidence from one.
        """
        owner, repo = self._split(repo_full_name)
        try:
            with self._client(installation_id) as github:
                response = github.request(
                    "GET",
                    f"/repos/{owner}/{repo}/contents/{path}",
                    params={"ref": ref},
                    headers={"Accept": "application/vnd.github.raw"},
                )
        except RequestFailed as exc:
            if exc.response.status_code == 404:
                # Ordinary: an added file has no image on the base commit.
                return None
            raise GitHubError(
                f"Could not read {path} at {ref[:7]} in {repo_full_name}: "
                f"HTTP {exc.response.status_code}"
            ) from exc
        except Exception as exc:
            raise GitHubError(
                f"Could not read {path} at {ref[:7]} in {repo_full_name}: {type(exc).__name__}"
            ) from exc

        # `githubkit.Response` is generic over the parsed model; with no `response_model` its
        # `content` is untyped, so the annotation is stated here rather than inferred as `Any`.
        content: bytes = response.content
        if len(content) > MAX_BLOB_BYTES:
            logger.info(
                "Skipping %s at %s: %s bytes is over the %s byte analysis budget",
                path,
                ref[:7],
                len(content),
                MAX_BLOB_BYTES,
            )
            return None

        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            # Not text. Decoding with errors="replace" would hand an agent a file of substitution
            # characters and let it report findings about bytes that were never there.
            logger.info("Skipping %s at %s: not valid UTF-8", path, ref[:7])
            return None

    def post_or_update_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        body: str,
        comment_id: int | None = None,
    ) -> int:
        owner, repo = self._split(repo_full_name)

        try:
            with self._client(installation_id) as github:
                if comment_id is not None:
                    try:
                        updated = github.rest.issues.update_comment(
                            owner, repo, comment_id, body=body
                        ).parsed_data
                        return int(updated.id)
                    except Exception:
                        # The comment is gone — somebody deleted it, or it belonged to a different
                        # repository after a transfer. Falling back to a new one keeps the review
                        # visible; refusing would mean the audit silently produced nothing.
                        logger.warning(
                            "Could not edit comment %s on %s#%s; posting a new one",
                            comment_id,
                            repo_full_name,
                            pr_number,
                        )

                created = github.rest.issues.create_comment(
                    owner, repo, pr_number, body=body
                ).parsed_data
                return int(created.id)
        except GitHubError:
            raise
        except Exception as exc:
            raise GitHubError(
                f"Could not comment on {repo_full_name}#{pr_number}: {type(exc).__name__}"
            ) from exc

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
        owner, repo = self._split(repo_full_name)

        payload: dict[str, Any] = {
            "body": body,
            "commit_id": commit_sha,
            "path": path,
            "line": line,
            "side": "RIGHT",
        }
        if start_line != line:
            # Only sent for a genuine multi-line anchor. GitHub rejects `start_line == line`
            # rather than treating it as a one-line span, so sending it unconditionally would
            # fail every single-line suggestion.
            payload["start_line"] = start_line
            payload["start_side"] = "RIGHT"

        try:
            with self._client(installation_id) as github:
                response = github.request(
                    "POST",
                    f"/repos/{owner}/{repo}/pulls/{pr_number}/comments",
                    json=payload,
                )
        except RequestFailed as exc:
            # 422 is the ordinary failure and it means the anchor is not in the diff. The patcher
            # already refuses to publish outside `changed_lines` (D-095), so reaching this is a
            # defect worth the status code in the message.
            raise GitHubError(
                f"Could not post a review comment on {repo_full_name}#{pr_number} "
                f"at lines {start_line}-{line}: HTTP {exc.response.status_code}"
            ) from exc
        except Exception as exc:
            raise GitHubError(
                f"Could not post a review comment on {repo_full_name}#{pr_number}: "
                f"{type(exc).__name__}"
            ) from exc

        created = response.json()
        return int(created["id"])
