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
from typing import Any, Protocol

import httpx
from githubkit import AppAuthStrategy, BaseAuthStrategy, GitHub

from codesheriff_worker.config import WorkerConfig

logger = logging.getLogger(__name__)


class GitHubError(RuntimeError):
    """GitHub refused or could not answer. Carries no token material."""


class GitHubGateway(Protocol):
    """What the pipeline asks of GitHub."""

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

    def post_or_update_comment(
        self,
        installation_id: int,
        repo_full_name: str,
        pr_number: int,
        body: str,
        comment_id: int | None = None,
    ) -> int:
        owner, _, repo = repo_full_name.partition("/")
        if not owner or not repo:
            raise GitHubError(f"Not a repository full name: {repo_full_name!r}")

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
