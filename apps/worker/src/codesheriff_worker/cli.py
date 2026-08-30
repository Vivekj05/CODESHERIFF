"""`codesheriff-worker` — operator commands that are not Celery tasks.

Today that is one thing: filling a repository's precedent store. It is a command rather than a
pipeline step on purpose (see `precedent/ingest.py`), so the store's contents do not depend on
which pull requests happened to be audited, in what order.
"""

from __future__ import annotations

import logging

import typer

from codesheriff_storage import StorageConfig, build_engine, build_session_factory, session_scope
from codesheriff_worker.config import WorkerConfig
from codesheriff_worker.github_gateway import GitHubKitGateway
from codesheriff_worker.precedent.embedding import load_embedder
from codesheriff_worker.precedent.ingest import ingest_merged_pr

app = typer.Typer(
    name="codesheriff-worker",
    help="CodeSheriff worker operations.",
    no_args_is_help=True,
)

precedent_app = typer.Typer(help="The precedent store that `context.rag` reasons from.")
app.add_typer(precedent_app, name="precedent")


@precedent_app.command("backfill")
def backfill(
    repository_id: int = typer.Option(..., help="GitHub repository id — stable across renames."),
    repo_full_name: str = typer.Option(..., help="owner/name, for the API calls."),
    installation_id: int = typer.Option(..., help="Installation whose token to mint."),
    pr: list[int] = typer.Option(..., "--pr", help="Merged PR number. Repeat for several."),
    head_sha: list[str] = typer.Option(
        ..., "--head-sha", help="Merge commit SHA for each --pr, in the same order."
    ),
) -> None:
    """Index the merged symbols of one or more pull requests.

    SHAs are passed rather than looked up so the command is explicit about which commit each
    excerpt was taken from — that value lands on the row, and a store that cannot say what it
    indexed cannot be re-derived.

    Idempotent per pull request, so an interrupted backfill is resumed by re-running it.
    """
    if len(pr) != len(head_sha):
        raise typer.BadParameter(
            f"{len(pr)} --pr value(s) and {len(head_sha)} --head-sha value(s); they pair up."
        )

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    gateway = GitHubKitGateway(WorkerConfig.load())
    embedder = load_embedder()
    factory = build_session_factory(build_engine(StorageConfig.load()))

    written = 0
    for number, sha in zip(pr, head_sha, strict=True):
        # One transaction per pull request. A backfill over a few hundred is going to be
        # interrupted, and a single transaction would lose everything indexed so far.
        with session_scope(factory) as db:
            result = ingest_merged_pr(
                db,
                gateway,
                embedder,
                installation_id=installation_id,
                repository_id=repository_id,
                repo_full_name=repo_full_name,
                pr_number=number,
                head_sha=sha,
            )
        if result.skipped:
            typer.echo(f"  #{number}: {result.skipped}")
            continue
        written += result.chunks_written
        typer.echo(
            f"  #{number}: {result.files_indexed} file(s), {result.chunks_written} symbol(s)"
        )

    typer.secho(f"{written} precedent chunk(s) written", fg=typer.colors.GREEN)


if __name__ == "__main__":
    app()
