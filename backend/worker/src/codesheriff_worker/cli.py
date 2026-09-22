"""`codesheriff-worker` — operator commands that are not Celery tasks.

Two things. Filling a repository's precedent store, which is a command rather than a pipeline
step on purpose (see `precedent/ingest.py`) so the store's contents do not depend on which pull
requests happened to be audited, in what order. And fitting the calibration artifact, which is a
command for a stronger version of the same reason: the numbers fusion multiplies with are
produced deliberately, from a named split, and recorded — never as a side effect of an audit.

The calibration commands are the only place in this process that reads the corpus. `lint-imports`
holds the audit path away from it (D-086).
"""

from __future__ import annotations

import logging

import typer

from codesheriff_corpus.models import Split
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

calibrate_app = typer.Typer(help="Fit the numbers fusion multiplies with (PLAN.md Chapter 14).")
app.add_typer(calibrate_app, name="calibrate")


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


# ---------------------------------------------------------------------------
# calibrate
# ---------------------------------------------------------------------------


def _split(value: str) -> Split:
    try:
        return Split(value)
    except ValueError:
        raise typer.BadParameter(
            f"unknown split {value!r}; one of calibration, validation"
        ) from None


@calibrate_app.command("observe")
def calibrate_observe(
    split: str = typer.Option("calibration", help="calibration or validation. Never test."),
) -> None:
    """Run all four agents over a split and write down what each said, per case.

    The slow half of a fit, and the half that has to be re-run when an agent changes. The
    output is committed, so `fit` is reproducible without a WASI interpreter, an API key or a
    Semgrep build.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from codesheriff_worker.calibration import observe, write

    observations = observe(_split(split))
    path = write(observations)

    typer.echo(
        f"{len(observations.claims)} claim(s) from {len(observations.primary())} case(s); "
        f"corpus {observations.corpus_hash[:12]} split {observations.split_hash[:12]}"
    )
    if observations.provenance.backends_silent:
        typer.secho(
            "silent on every unit: " + ", ".join(observations.provenance.backends_silent),
            fg=typer.colors.YELLOW,
        )
    typer.secho(f"wrote {path}", fg=typer.colors.GREEN)


@calibrate_app.command("record")
def calibrate_record(
    split: str = typer.Option("validation", help="Which split to ask the model about."),
    all_cases: bool = typer.Option(
        False, "--all", help="Re-record cases that already have a response. Rarely right."
    ),
) -> None:
    """Record the semantic witness's answers for cases that have none.

    The only command here that calls a provider. Its output is committed and replayed by every
    later `observe`, so a fit stays reproducible and free.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from codesheriff_worker.calibration import record_split

    report = record_split(_split(split), missing_only=not all_cases)
    typer.echo(f"recorded {report.written}, already had {report.skipped}")
    if report.failed:
        typer.secho(f"no answer for: {', '.join(report.failed)}", fg=typer.colors.RED)
        raise typer.Exit(1)


@calibrate_app.command("fit")
def calibrate_fit(
    base_rate: float = typer.Option(
        0.03,
        help="Declared production base rate. Rescales the prior; refits nothing.",
    ),
    out: str = typer.Option("", help="Where to write. Defaults to the packaged artifact."),
    notes: str = typer.Option("", help="Anything a reader of the artifact should know."),
) -> None:
    """Fit ratios on calibration, select the threshold on validation, write calibration.json.

    Reads the committed observations rather than re-running the agents, so the artifact is
    reproducible from files in the repository — which is what §6 asks of a fitted number.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    from pathlib import Path

    from codesheriff_worker.calibration import fit_from_observations, read, write_artifact

    artifact = fit_from_observations(
        read(Split.CALIBRATION),
        read(Split.VALIDATION),
        base_rate=base_rate,
        notes=notes,
    )
    path = write_artifact(artifact, Path(out) if out else None)

    for witness, fitted in sorted(artifact.fit.witnesses.items()):
        ratios = fitted.ratios()
        typer.echo(
            f"  {witness:<11} high {ratios.detection_high:6.2f}  med {ratios.detection_medium:6.2f}"
            f"  low {ratios.detection_low:6.2f}  silence {ratios.silence:5.2f}"
            f"   (+{fitted.n_vulnerable_claims}/-{fitted.n_safe_claims} spoke,"
            f" {fitted.n_abstained} abstained)"
        )
    typer.echo(f"  prior {artifact.prior.base_rate:.1%} ({artifact.prior.source})")
    typer.echo(f"  {artifact.threshold.note}")
    validation = artifact.metrics.get("validation")
    if validation is not None:
        typer.echo(f"  validation ECE {validation.ece:.3f}  Brier {validation.brier:.3f}")
    typer.secho(f"wrote {path}", fg=typer.colors.GREEN)


@calibrate_app.command("show")
def calibrate_show() -> None:
    """What the active artifact says, and where it came from."""
    from codesheriff_engine.calibration import active_artifact, artifact_path

    artifact = active_artifact()
    typer.echo(f"{artifact_path()}")
    typer.echo(artifact.summary())


if __name__ == "__main__":
    app()
