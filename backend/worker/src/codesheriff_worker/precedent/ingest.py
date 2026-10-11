"""Filling the precedent store from a repository's merged pull requests.

**A backfill, not a pipeline step.** Nothing in the audit path writes precedent. An audit that
also ingested would make the store's contents depend on which pull requests happened to be
reviewed, in what order, and would put a write transaction inside a read the agents are
already running concurrently against. Keeping ingestion an explicit command also means a
corpus run can stand up a precedent store with no GitHub credentials at all, which is what
Chapter 14 needs.

**One chunk per symbol** (PROJECT_CONTEXT.md §5), never per pull request.
`bge-small-en-v1.5` truncates at 512 tokens, so a PR-level document is silently cut and matches
poorly against a function-level query — and a per-PR vector cannot answer "which symbol carried
this guard", which is the only question the context agent asks.

**The merged side only.** Precedent is what the repository *accepted*; the base version of a
file in a merged PR is what it accepted previously and is already precedent from an earlier
merge. Indexing both would let a control that a pull request deliberately *removed* go on
establishing itself forever.

Excerpts are clipped by `redact_chunk` before they become rows (D-027), and the hash is taken
of the clipped text, because a hash of something the database does not hold cannot be checked
against anything.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from codesheriff_engine.extraction import (
    is_analysable_path,
    is_test_path,
    parse_python_file,
    qualified,
)
from codesheriff_storage.models import PRPrecedent
from codesheriff_storage.precedents import build_chunk
from codesheriff_worker.github_gateway import GitHubGateway
from codesheriff_worker.precedent.embedding import (
    EMBEDDING_MODEL_NAME,
    PrecedentEmbedder,
    query_text,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class IngestResult:
    """What one pull request contributed."""

    pr_number: int
    files_indexed: int
    chunks_written: int
    skipped: str | None = None


def ingest_merged_pr(
    session: Session,
    gateway: GitHubGateway,
    embedder: PrecedentEmbedder,
    *,
    installation_id: int,
    repository_id: int,
    repo_full_name: str,
    pr_number: int,
    head_sha: str,
) -> IngestResult:
    """Index every changed Python symbol of one merged pull request.

    Idempotent by `(repository_id, pr_number)` — the unique constraint the model already
    carries. Re-running skips what is present rather than raising, because a backfill over a
    few hundred pull requests will be interrupted and resumed, and a command that cannot be
    resumed is one that gets run with `--force` instead.
    """
    existing = session.scalar(
        select(PRPrecedent).where(
            PRPrecedent.repository_id == repository_id,
            PRPrecedent.pr_number == pr_number,
        )
    )
    if existing is not None:
        return IngestResult(pr_number, 0, 0, skipped="already ingested")

    listed = gateway.list_pull_request_files(installation_id, repo_full_name, pr_number)
    paths = [
        entry.path
        for entry in listed
        if entry.status != "removed"
        and is_analysable_path(entry.path)
        # Test files establish nothing about how production endpoints are guarded, and a
        # repository has many more of them. Indexing them would let test helpers dominate
        # retrieval for every query.
        and not is_test_path(entry.path)
    ]

    precedent = PRPrecedent(
        repository_id=repository_id,
        pr_number=pr_number,
        head_sha=head_sha,
        files_changed=len(paths),
    )
    session.add(precedent)
    session.flush()

    written = 0
    indexed_files = 0
    for path in paths:
        source = gateway.get_file_at_ref(installation_id, repo_full_name, path, head_sha)
        if source is None:
            logger.info("%s#%s: no blob for %s at %s", repo_full_name, pr_number, path, head_sha)
            continue

        try:
            parsed = parse_python_file(source)
        except Exception as exc:
            logger.warning("%s: could not parse %s: %s", repo_full_name, path, exc)
            continue

        indexed_files += 1
        for index, symbol in enumerate(parsed.symbols):
            name = qualified(symbol.enclosing_class, symbol.name)
            session.add(
                build_chunk(
                    precedent_id=precedent.id,
                    file=path,
                    content=symbol.source,
                    embedding=embedder.embed(query_text(path, name, symbol.source)),
                    chunk_index=index,
                    qualified_symbol=name,
                    embedding_model=EMBEDDING_MODEL_NAME,
                )
            )
            written += 1

    logger.info(
        "%s#%s: indexed %s file(s), %s symbol(s)",
        repo_full_name,
        pr_number,
        indexed_files,
        written,
    )
    return IngestResult(pr_number, indexed_files, written)
