"""Typer CLI interface for static-agent."""

import json
import sys
from pathlib import Path

import typer
from pydantic import ValidationError

from codesheriff_contracts import ChangeUnit, EvidenceKind
from static_agent.agent import StaticAgent

app = typer.Typer(help="CodeSheriff Static Agent CLI")


@app.command()
def run(
    input_file: str = typer.Argument(..., help="Path to ChangeUnit JSON file, or '-' for stdin"),
    pretty: bool = typer.Option(False, "--pretty", help="Pretty print output JSON"),
) -> None:
    """Run static security analysis on a ChangeUnit JSON input."""
    try:
        if input_file == "-":
            raw_json = sys.stdin.read()
        else:
            p = Path(input_file)
            if not p.exists():
                typer.echo(f"Error: file not found '{input_file}'", err=True)
                sys.exit(2)
            raw_json = p.read_text(encoding="utf-8")

        unit_dict = json.loads(raw_json)
        unit = ChangeUnit(**unit_dict)
    except (json.JSONDecodeError, ValidationError, Exception) as e:
        typer.echo(f"Error reading ChangeUnit input: {e!s}", err=True)
        sys.exit(2)

    agent = StaticAgent()
    evidence_list = agent.analyze(unit)

    output = [e.model_dump() for e in evidence_list]
    indent = 2 if pretty else None
    print(json.dumps(output, indent=indent, default=str))
    sys.exit(0)


@app.command()
def explain(
    input_file: Path = typer.Argument(..., help="Path to ChangeUnit JSON file"),
) -> None:
    """Print human-readable taint path chains for reported findings."""
    if not input_file.exists():
        typer.echo(f"Error: file not found '{input_file}'", err=True)
        sys.exit(2)

    try:
        unit = ChangeUnit(**json.loads(input_file.read_text(encoding="utf-8")))
    except Exception as e:
        typer.echo(f"Error reading ChangeUnit: {e!s}", err=True)
        sys.exit(2)

    agent = StaticAgent()
    evidence_list = agent.analyze(unit)

    if not any(e.kind is EvidenceKind.DETECTION for e in evidence_list):
        typer.echo("No active vulnerability findings detected.")
        sys.exit(0)

    for idx, ev in enumerate(evidence_list, start=1):
        if ev.kind is not EvidenceKind.DETECTION:
            continue
        typer.echo(
            f"\n--- Finding #{idx}: [{ev.cwe}] Key: {ev.finding_key} (Score: {ev.raw_score}) ---"
        )
        typer.echo(f"Explanation: {ev.explanation}")
        for art in ev.artifacts:
            if art.artifact_type == "taint_path" and isinstance(art.content, dict):
                typer.echo("Taint Path Execution Chain:")
                steps = art.content.get("steps", [])
                for s in steps:
                    typer.echo(
                        f"  Line {s.get('line', '?'):>3} "
                        f"[{s.get('role', 'propagation'):<11}]: {s.get('expr', '')}"
                    )
    sys.exit(0)


# There is no `bench` command, and there must not be one here.
#
# It took a `--corpus` path, ignored it, and printed `precision: 1.0, recall: 1.0, fpr: 0.0` —
# fabricated metrics that D-010 requires deleted so that nothing in this repository can report
# perfect scores again. The measurement it pretended to be is real now and lives in
# `tests/test_corpus_calibration.py`, where it runs against the labelled corpus on the calibration
# split and fails when recall drops.
#
# It belongs in a test rather than a command for a reason that outlasts this chapter: §6 permits
# the test split to be evaluated exactly once, at the end, and a CLI anyone can point at any split
# is precisely how that gets violated by accident. Chapter 14 owns the evaluation harness and the
# split discipline that goes with it.


@app.command()
def version() -> None:
    """Print agent version information."""
    agent = StaticAgent()
    info = {
        "agent_id": agent.id,
        "agent_version": agent.version,
    }
    print(json.dumps(info))
    sys.exit(0)


if __name__ == "__main__":
    app()
