"""`codesheriff-corpus` — inspect the corpus, and assign splits once.

`assign` is the only command that writes, and it will not move a pair that already
has a split. Re-running it after adding cases places the new ones and leaves every
existing assignment untouched.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from pathlib import Path

import typer

from codesheriff_corpus.hashing import corpus_hash, split_hash
from codesheriff_corpus.loader import CorpusError, load_cases, load_pairs
from codesheriff_corpus.models import KNOWN_AGENT_IDS, Label, Split
from codesheriff_corpus.splits import (
    DEFAULT_RATIOS,
    SPLITS_FILENAME,
    SplitFile,
    assign,
    load_splits,
    read_splits_file,
    write_splits,
)

app = typer.Typer(help="Inspect and split the CodeSheriff corpus.", no_args_is_help=True)


@app.command()
def validate() -> None:
    """Load every case and report what would fail CI."""
    try:
        cases = load_cases()
        pairs = load_pairs()
    except CorpusError as exc:
        typer.secho(f"corpus does not load: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(1) from exc

    typer.echo(f"{len(cases)} cases in {len(pairs)} twin pairs")
    typer.echo(f"corpus_hash  {corpus_hash()}")

    try:
        typer.echo(f"split_hash   {split_hash()}")
    except CorpusError as exc:
        typer.secho(f"splits: {exc}", fg=typer.colors.YELLOW, err=True)
        raise typer.Exit(1) from exc

    typer.secho("corpus is consistent", fg=typer.colors.GREEN)


@app.command()
def stats() -> None:
    """Coverage by CWE, split and agent. The table that goes in the paper."""
    cases = load_cases()
    assignments = load_splits().assignments

    typer.echo(f"{'CWE':<10}{'vuln':>6}{'safe':>6}{'calib':>8}{'valid':>8}{'test':>7}")
    by_cwe: dict[str, list[str]] = {}
    for case in cases:
        by_cwe.setdefault(case.cwe, []).append(case.case_id)

    for cwe in sorted(by_cwe, key=lambda c: int(c.removeprefix("CWE-"))):
        members = [c for c in cases if c.cwe == cwe]
        counts = Counter(assignments[c.pair_id] for c in members)
        typer.echo(
            f"{cwe:<10}"
            f"{sum(1 for c in members if c.is_vulnerable):>6}"
            f"{sum(1 for c in members if not c.is_vulnerable):>6}"
            f"{counts[Split.CALIBRATION]:>8}"
            f"{counts[Split.VALIDATION]:>8}"
            f"{counts[Split.TEST]:>7}"
        )

    totals = Counter(assignments[c.pair_id] for c in cases)
    typer.echo(
        f"\n{'total':<10}"
        f"{sum(1 for c in cases if c.is_vulnerable):>6}"
        f"{sum(1 for c in cases if not c.is_vulnerable):>6}"
        f"{totals[Split.CALIBRATION]:>8}"
        f"{totals[Split.VALIDATION]:>8}"
        f"{totals[Split.TEST]:>7}"
    )

    typer.echo("\ndetectable_by, over vulnerable cases:")
    vulnerable = [c for c in cases if c.is_vulnerable]
    for agent_id in sorted(KNOWN_AGENT_IDS):
        n = sum(1 for c in vulnerable if c.detectable(agent_id))
        typer.echo(f"  {agent_id:<20}{n:>3} / {len(vulnerable)}")


@app.command(name="hash")
def hash_() -> None:
    """Print the two hashes a calibration run has to record (PROJECT_CONTEXT.md §6)."""
    typer.echo(f"corpus_hash  {corpus_hash()}")
    typer.echo(f"split_hash   {split_hash()}")


@app.command(name="assign")
def assign_(
    seed: int = typer.Option(..., help="Recorded in splits.json so the draw can be re-derived."),
    out: Path = typer.Option(
        Path(__file__).parent / SPLITS_FILENAME,
        help="Where to write. Defaults to the committed file.",
    ),
    notes: str = typer.Option("", help="Why this assignment was made."),
) -> None:
    """Place unassigned pairs. Never moves a pair that already has a split."""
    # Read the file directly rather than through `load_splits`, which refuses a
    # half-assigned corpus — the state this command exists to resolve. Catching that
    # refusal and continuing with nothing is how a re-run came to re-draw every settled
    # pair instead of extending them (D-069).
    committed = read_splits_file()
    existing = dict(committed.assignments) if committed else {}

    if existing:
        typer.secho(f"keeping {len(existing)} existing assignments", fg=typer.colors.YELLOW)

    assignments = assign(seed=seed, existing=existing)
    added = len(assignments) - len(existing)

    write_splits(
        SplitFile(
            generated=dt.date.today().isoformat(),
            seed=seed,
            ratios=DEFAULT_RATIOS,
            assignments=assignments,
            notes=notes,
        ),
        str(out),
    )

    counts = Counter(assignments.values())
    typer.echo(f"wrote {out} ({added} newly assigned, {len(existing)} unchanged)")
    for split in Split:
        typer.echo(f"  {split.value:<12}{counts[split]:>3} pairs")
    typer.echo(f"split_hash   {split_hash()}")


@app.command()
def show(case_id: str) -> None:
    """One case: its label, its key, and what it looks like to an agent."""
    from codesheriff_corpus.loader import case_by_id

    case = case_by_id(case_id)
    typer.echo(f"{case.case_id}  [{case.label.value}]  {case.cwe}")
    typer.echo(f"  pair          {case.pair_id}")
    typer.echo(f"  symbol        {case.unit.qualified_symbol}  ({case.file})")
    typer.echo(f"  finding_key   {case.expected_key}")
    typer.echo(f"  changed_lines {case.changed_lines}")
    if case.label is Label.VULNERABLE:
        typer.echo(f"  detectable_by {', '.join(sorted(case.detectable_by))}")
    typer.echo(f"  rationale     {case.rationale}")


if __name__ == "__main__":
    app()
