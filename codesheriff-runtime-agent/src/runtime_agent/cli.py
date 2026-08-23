"""Typer CLI interface for Runtime Agent."""

import json
from pathlib import Path
import typer
from runtime_agent import __version__
from runtime_agent.agent import RuntimeAgent
from runtime_agent.contracts import ChangeUnit

app = typer.Typer(
    name="runtime-agent",
    help="SFI Runtime Execution Security Agent CLI",
    add_completion=False,
)


@app.command(name="run")
def run(
    unit_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to JSON file containing ChangeUnit payload",
    )
) -> None:
    """Analyze a ChangeUnit payload file for runtime SFI vulnerabilities."""
    try:
        data = json.loads(unit_file.read_text(encoding="utf-8"))
        unit = ChangeUnit.model_validate(data)
    except Exception as e:
        typer.secho(f"Error loading ChangeUnit JSON: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    agent = RuntimeAgent()
    evidence_list = agent.analyze(unit)

    out = [ev.model_dump() for ev in evidence_list]
    typer.echo(json.dumps(out, indent=2))


@app.command(name="health")
def health() -> None:
    """Print health status of Runtime Agent."""
    typer.echo(json.dumps({"status": "ok", "agent_id": "runtime.sfi", "version": __version__}))


@app.command(name="version")
def version() -> None:
    """Print version string."""
    typer.echo(f"runtime-agent v{__version__}")


if __name__ == "__main__":
    app()
