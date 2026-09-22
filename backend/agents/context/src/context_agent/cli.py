"""`context-agent` — run the context witness over one change unit.

`ingest` and `search` are gone with the local store they drove (D-016, `AUDIT.md` 0.2).
Precedent is written and queried by `apps/worker`, which owns the pgvector session and the
embedding model; a CLI in an agent package that could fill a vector store would be an agent
that knows about infrastructure, which `lint-imports` fails the build for.

`run` therefore analyses against whatever history it is given, and with none it abstains —
which is the honest result and is exactly what production does on a repository nobody has
ingested yet. `--precedent` takes a JSON array so the reasoning can be exercised by hand:

    [{"pr_number": 118, "file": "app/admin/users.py",
      "qualified_symbol": "export_users", "accepted_src": "...", "similarity": 0.9}]
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from codesheriff_contracts import ChangeUnit
from context_agent import __version__
from context_agent.agent import ContextAgent
from context_agent.classify import COVERED_CWES
from context_agent.config import AGENT_ID, AGENT_VERSION, ContextConfig
from context_agent.precedent import Precedent

app = typer.Typer(
    name="context-agent",
    help="CodeSheriff context witness: cross-PR security control regressions.",
    no_args_is_help=True,
)


class _StaticRetriever:
    """Serves a fixed list. The repository filter is the caller's problem here, not this
    agent's — production scoping is structural and lives in `apps/worker`."""

    def __init__(self, precedents: list[Precedent]) -> None:
        self._precedents = precedents

    def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
        return self._precedents[:limit]


@app.command()
def run(
    unit_path: Path = typer.Argument(
        ..., help="Path to a ChangeUnit JSON file", exists=True, readable=True
    ),
    precedent_path: Path | None = typer.Option(
        None,
        "--precedent",
        "-p",
        help="JSON array of merged excerpts to treat as this repository's history.",
        exists=True,
        readable=True,
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the Evidence array"),
) -> None:
    """Analyse a ChangeUnit against a precedent history."""
    unit = ChangeUnit.model_validate(json.loads(unit_path.read_text(encoding="utf-8")))

    precedents: list[Precedent] = []
    if precedent_path is not None:
        raw = json.loads(precedent_path.read_text(encoding="utf-8"))
        precedents = [Precedent(**entry) for entry in raw]

    # No `--anchor` flag, and there will not be one: agents run blind (D-008).
    agent = ContextAgent(retriever=_StaticRetriever(precedents) if precedents else None)
    evidence = agent.analyze(unit)

    rendered = json.dumps([e.model_dump(mode="json") for e in evidence], indent=2)
    if output:
        output.write_text(rendered, encoding="utf-8")
        typer.echo(f"Evidence written to {output}")
    else:
        typer.echo(rendered)


@app.command()
def version() -> None:
    """Identity and the settings that shape a run."""
    cfg = ContextConfig.load()
    typer.echo(f"CodeSheriff context agent v{__version__}")
    typer.echo(f"  agent_id       {AGENT_ID} ({AGENT_VERSION})")
    typer.echo(f"  covered_cwes   {', '.join(sorted(COVERED_CWES))}")
    typer.echo(f"  top_k          {cfg.top_k}")
    typer.echo(f"  min_similarity {cfg.min_similarity}  (provisional until Chapter 14)")


if __name__ == "__main__":
    app()
