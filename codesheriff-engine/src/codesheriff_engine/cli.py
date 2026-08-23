"""Command-line interface for CodeSheriff Fusion Engine."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional
import typer
import uvicorn

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from codesheriff_engine.config import EngineConfig
from codesheriff_engine.contracts import CONTRACT_VERSION, ChangeUnit
from codesheriff_engine.github.reporter import format_github_comment
from codesheriff_engine.orchestrator import Orchestrator

app = typer.Typer(
    name="codesheriff-engine",
    help="CodeSheriff Bayesian Fusion & Multi-Agent Integration Engine CLI",
    add_completion=False,
)


@app.command()
def version() -> None:
    """Print package and contract version."""
    typer.echo(f"codesheriff-engine v0.1.0 (Contract: v{CONTRACT_VERSION})")


@app.command()
def run(
    unit_path: Path = typer.Argument(..., help="Path to ChangeUnit JSON file"),
    debate: bool = typer.Option(True, help="Enable multi-agent debate on conflicting scores"),
    output_markdown: bool = typer.Option(False, "--markdown", "-m", help="Output formatted GitHub Markdown"),
) -> None:
    """Run full multi-agent Bayesian security audit on a ChangeUnit JSON."""
    if not unit_path.exists():
        typer.secho(f"Error: File not found at '{unit_path}'", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        raw_data = json.loads(unit_path.read_text(encoding="utf-8"))
        unit = ChangeUnit.model_validate(raw_data)
    except Exception as e:
        typer.secho(f"Error: Failed to parse ChangeUnit JSON: {e}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    config = EngineConfig.load()
    orchestrator = Orchestrator(config=config)

    typer.secho(f"[*] Analyzing unit '{unit.unit_id}' in {unit.file}...", fg=typer.colors.CYAN)
    results = asyncio.run(orchestrator.analyze_change_unit(unit, run_debate=debate))

    if output_markdown:
        comment = format_github_comment(results, pr_title=f"Unit {unit.unit_id}")
        try:
            typer.echo(comment)
        except UnicodeEncodeError:
            sys.stdout.buffer.write((comment + "\n").encode("utf-8", errors="replace"))
        return

    typer.echo("\n" + "=" * 60)
    typer.secho(f"[+] BAYESIAN FUSION AUDIT REPORT ({len(results)} findings)", fg=typer.colors.BRIGHT_WHITE, bold=True)
    typer.echo("=" * 60)

    for idx, f in enumerate(results, start=1):
        alert_tag = "[ALERT]" if f.is_alert_worthy else "[SAFE]"
        color = typer.colors.RED if f.is_alert_worthy else typer.colors.GREEN

        typer.secho(
            f"\n#{idx} {alert_tag} {f.title or 'Security Finding'} | Posterior P(V): {f.posterior_probability * 100:.1f}%",
            fg=color,
            bold=True,
        )
        typer.echo(f"   Finding Key : {f.finding_key}")
        typer.echo(f"   CWE         : {f.cwe or 'N/A'}")
        typer.echo(f"   Severity    : {f.severity or 'N/A'}")
        typer.echo("   Agent Breakdown:")

        for ev in f.evidence_list:
            ev_status = "[ABSTAIN]" if ev.abstained else f"Score: {ev.raw_score:.2f}"
            typer.echo(f"     - {ev.agent_id:<18} : {ev_status:<12} | {ev.explanation[:70]}")

        if f.consensus_rationale:
            typer.secho(f"   Debate Consensus: {f.consensus_rationale}", fg=typer.colors.YELLOW)

    typer.echo("\n" + "=" * 60)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host address to bind"),
    port: int = typer.Option(8000, help="Port to listen on"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
) -> None:
    """Start the FastAPI GitHub Webhook server."""
    typer.secho(f"[*] Starting CodeSheriff Engine server on {host}:{port}...", fg=typer.colors.GREEN)
    uvicorn.run("codesheriff_engine.main:app", host=host, port=port, reload=reload)


if __name__ == "__main__":
    app()
