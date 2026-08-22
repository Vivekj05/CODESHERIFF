"""Command line interface for CodeSheriff Semantic Agent."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Optional
import typer

from semantic_agent import __version__
from semantic_agent.agent import SemanticAgent
from semantic_agent.config import SemanticConfig
from semantic_agent.contracts import ChangeUnit

app = typer.Typer(
    name="semantic-agent",
    help="CodeSheriff Semantic Agent Security Reviewer CLI",
)


@app.command()
def run(
    unit_path: Path = typer.Argument(
        ...,
        help="Path to ChangeUnit JSON file",
        exists=True,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path for Evidence JSON array",
    ),
) -> None:
    """Analyze a single ChangeUnit payload file."""
    content = unit_path.read_text(encoding="utf-8")
    data = json.loads(content)
    unit = ChangeUnit.model_validate(data)

    agent = SemanticAgent()
    evidence_list = agent.analyze(unit)
    out_data = [ev.model_dump() for ev in evidence_list]

    json_str = json.dumps(out_data, indent=2)
    if output:
        output.write_text(json_str, encoding="utf-8")
        typer.echo(f"Evidence written to {output}")
    else:
        typer.echo(json_str)


@app.command()
def bench(
    corpus_dir: Path = typer.Option(
        Path("corpus"),
        "--corpus-dir",
        help="Directory containing benchmark ChangeUnit JSON files",
    ),
) -> None:
    """Run benchmark evaluation suite across labeled vulnerability corpus."""
    if not corpus_dir.exists():
        typer.echo(f"Corpus directory {corpus_dir} not found.", err=True)
        raise typer.Exit(code=1)

    files = list(corpus_dir.glob("*.json"))
    typer.echo(f"Running benchmark on {len(files)} corpus units...")

    agent = SemanticAgent()
    findings_count = 0
    abstentions_count = 0

    for f in files:
        data = json.loads(f.read_text(encoding="utf-8"))
        unit = ChangeUnit.model_validate(data)
        ev_list = agent.analyze(unit)
        for ev in ev_list:
            if ev.abstained:
                abstentions_count += 1
            else:
                findings_count += 1

    typer.echo(f"Benchmark Complete: {len(files)} files processed.")
    typer.echo(f"Findings emitted: {findings_count}, Abstentions: {abstentions_count}")


@app.command()
def replay(
    unit_path: Path = typer.Argument(..., help="Path to ChangeUnit JSON file"),
) -> None:
    """Replay evaluation using local cache without live API calls."""
    run(unit_path=unit_path, output=None)


@app.command()
def injection_test(
    corpus_dir: Path = typer.Option(
        Path("injection_corpus"),
        "--corpus-dir",
        help="Directory containing prompt injection benchmark units",
    ),
) -> None:
    """Test resilience against prompt injection attacks."""
    typer.echo("Running prompt injection defense evaluation...")
    if not corpus_dir.exists():
        typer.echo(f"Injection corpus dir {corpus_dir} not found. Skipping.")
        return
    bench(corpus_dir=corpus_dir)


@app.command()
def version() -> None:
    """Display Semantic Agent version and configuration."""
    cfg = SemanticConfig.load()
    typer.echo(f"CodeSheriff Semantic Agent v{__version__}")
    typer.echo(f"Agent ID: {cfg.agent_id}")
    typer.echo(f"Model: {cfg.model}")
    typer.echo(f"Temperature: {cfg.temperature}")
    typer.echo(f"N Samples: {cfg.n_samples}")
    typer.echo(f"Budget USD/unit: ${cfg.budget_usd_per_unit:.3f}")


if __name__ == "__main__":
    app()
