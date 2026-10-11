"""Fetching the blobs an audit needs, and turning them into change units.

The division of labour is the point of this module. `codesheriff_engine.extraction` decides *what
a unit is* and holds no client of any kind; this decides *what to fetch* and holds nothing about
the shape of a unit. Chapter 14 runs the first half over corpus cases with no credentials at all,
which is only possible while the two stay apart.

**Both sides of every changed file are fetched, and the diff is never parsed.** GitHub omits
`patch` on a large diff, and the superseded parser skipped those files without saying so
(`AUDIT.md` 4.1) while reconstructing broken source from the patches it did get (`AUDIT.md` 4.2).
Fetching the two blobs makes the large-diff case identical to every other case rather than a
branch that has to be remembered.
"""

from __future__ import annotations

import logging

from codesheriff_engine.extraction import (
    ExtractionResult,
    FetchedFile,
    SkipReason,
    extract_units,
    is_analysable_path,
)
from codesheriff_worker.github_gateway import GitHubGateway, PullRequestFile

logger = logging.getLogger(__name__)

STATUSES_WITHOUT_A_BASE_IMAGE: frozenset[str] = frozenset({"added", "copied"})
"""Statuses for which the base commit holds nothing to compare against.

Asking for the pre-image anyway would spend an API call to be told 404, and `pre_src=None` is what
the contract already means by "there is no before".
"""


def fetch_and_extract(
    gateway: GitHubGateway,
    *,
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
) -> ExtractionResult:
    """Every changed function of one pull request, and a record of what was skipped."""
    listed = gateway.list_pull_request_files(installation_id, repo_full_name, pr_number)
    fetched = [
        _fetch_one(gateway, entry, installation_id, repo_full_name, base_sha, head_sha)
        for entry in listed
    ]
    result = extract_units(fetched, repo=repo_full_name, base_sha=base_sha, head_sha=head_sha)
    logger.info(
        "%s#%s: %s files listed, %s units extracted, %s files skipped",
        repo_full_name,
        pr_number,
        len(listed),
        len(result.units),
        len(result.skipped),
    )
    return result


def _fetch_one(
    gateway: GitHubGateway,
    entry: PullRequestFile,
    installation_id: int,
    repo_full_name: str,
    base_sha: str,
    head_sha: str,
) -> FetchedFile:
    """Both images of one changed file, or the reason there are none.

    A file the extractor would skip anyway is never fetched. The two decisions use one predicate —
    `is_analysable_path` — so a file cannot be fetched and then dropped, or dropped without ever
    being considered.
    """
    if entry.status == "removed" or not is_analysable_path(entry.path):
        return FetchedFile(path=entry.path, status=entry.status)

    post_src = gateway.get_file_at_ref(installation_id, repo_full_name, entry.path, head_sha)
    if post_src is None:
        # The gateway returns None for a file that is absent, oversized or not UTF-8, and raises
        # for anything it did not expect. Guessing which of the three this was would put a reason
        # in the audit record that nobody checked, so the general one stands.
        return FetchedFile(
            path=entry.path,
            status=entry.status,
            unavailable_reason=SkipReason.CONTENT_UNAVAILABLE,
        )

    pre_src: str | None = None
    if entry.status not in STATUSES_WITHOUT_A_BASE_IMAGE:
        # A rename's pre-image lives at the old path. Reading the new path on the base commit
        # would 404, the file would look new, and every line of it would read as changed — an
        # audit that reports a rename as a rewrite.
        pre_src = gateway.get_file_at_ref(
            installation_id, repo_full_name, entry.previous_path or entry.path, base_sha
        )

    return FetchedFile(
        path=entry.path,
        status=entry.status,
        post_src=post_src,
        pre_src=pre_src,
    )
