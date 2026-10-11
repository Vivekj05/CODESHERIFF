"""`runtime-agent` - report on the sandbox, and drive one file through it by hand.

`doctor` exists because the difference between "the interpreter has not been fetched" and
"the sandbox is broken" is one command rather than a debugging session, and because an
abstention that says `interpreter_unavailable` on every unit is otherwise indistinguishable
from an agent that is quietly doing nothing (D-077).

Nothing here downloads anything. `doctor` prints the URL and the digest; fetching is a
deliberate act by a person, because an agent that pulled executable code over the network
at analysis time would be the supply-chain problem this project exists to notice.
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from agent_runtime.config import INTERPRETER_SHA256, RuntimeConfig
from agent_runtime.interpreter import RELEASE_URL, search

app = typer.Typer(help="runtime.sfi - Wasmtime + WASI sandbox diagnostics.", no_args_is_help=True)


@app.command()
def doctor() -> None:
    """Report whether the sandbox can run, and exactly where it looked."""
    config = RuntimeConfig.load()
    result = search(config)

    typer.echo("runtime.sfi sandbox")
    typer.echo(f"  fuel            {config.fuel:,} instructions")
    typer.echo(f"  wall clock      {config.wall_clock_seconds}s")
    typer.echo(f"  memory ceiling  {config.memory_bytes // (1024 * 1024)} MiB")
    typer.echo("  capabilities    no network, no filesystem, no environment")
    typer.echo("")
    typer.echo("interpreter search")
    for candidate in result.searched:
        mark = "found" if result.found == candidate else "     "
        typer.echo(f"  [{mark}] {candidate}")

    if result.found is None:
        typer.echo("")
        typer.echo("  NOT FOUND. The agent will abstain 'interpreter_unavailable' on every unit,")
        typer.echo("  which costs the posterior nothing but leaves you with three witnesses.")
        typer.echo(f"  Fetch:  {RELEASE_URL}")
        typer.echo(f"  sha256: {INTERPRETER_SHA256}")
        raise typer.Exit(code=1)

    typer.echo("")
    typer.echo(f"  digest   {result.digest}")
    typer.echo(f"  expected {INTERPRETER_SHA256}")
    if not result.digest_matches:
        typer.echo("  MISMATCH - the agent refuses to execute untrusted code in an interpreter")
        typer.echo("  it was not measured against.")
        raise typer.Exit(code=1)
    typer.echo("  ok")


@app.command()
def probe(
    path: Path = typer.Argument(..., help="A Python file holding the function to drive."),
    symbol: str = typer.Argument(..., help="The function to call."),
    imports: str = typer.Option("", help="Comma-separated dotted imports, e.g. flask.send_file"),
) -> None:
    """Run one function through the sandbox and print the evidence, as JSON.

    For inspecting a single case by hand. The pipeline never calls this - `apps/worker`
    constructs a `ChangeUnit` from a pull request and calls `analyze` directly.
    """
    from agent_runtime.agent import RuntimeAgent
    from codesheriff_contracts import ChangeUnit

    unit = ChangeUnit(
        unit_id=f"cli:{path.name}:{symbol}",
        repo="local/cli",
        language="python",
        file=str(path),
        symbol=symbol,
        post_src=path.read_text(encoding="utf-8"),
        imports=[i.strip() for i in imports.split(",") if i.strip()],
        base_sha="0" * 40,
        head_sha="0" * 40,
    )
    evidence = RuntimeAgent().analyze(unit)
    typer.echo(json.dumps([e.model_dump(mode="json") for e in evidence], indent=2))


if __name__ == "__main__":  # pragma: no cover
    app()
