"""Command-line interface for the fusion engine.

Two commands, and neither runs an agent. Running agents is `apps/worker`'s job — see the
package docstring — so what is left here is the arithmetic: hand it evidence, and it shows
you the posterior and the factor each witness contributed to it.

That is the useful thing to have at a prompt anyway. "Why is this 31% and not 96%" is
answered by the breakdown below, and answering it needed a full analysis run before.

No `serve` command. It booted `codesheriff_engine.main:app`, a second FastAPI application
that mounted the unauthenticated webhook — worse than the webhook itself, because it was a
supported way to start it. Both were deleted in Chapter 6. The API is
`uvicorn codesheriff_api.main:app`.

No `--markdown` either. `codesheriff_engine.reporting` rendered a second pull request
comment, complete with the file path that D-050 keeps out of one, and diverging from the
comment the worker actually posts. `apps/worker/comment.py` is the only place a comment
body is built.
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path

import typer

# Ensure UTF-8 output encoding on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from codesheriff_contracts import CONTRACT_VERSION, Evidence, EvidenceKind
from codesheriff_engine.config import EngineConfig
from codesheriff_engine.fusion import Stance, fuse_all_evidence

app = typer.Typer(
    name="codesheriff-engine",
    help="CodeSheriff Bayesian fusion engine CLI",
    add_completion=False,
)

_STANCE_TAG = {
    Stance.DETECTED: "DETECTED",
    Stance.SILENT: "SILENT",
    Stance.NEUTRAL: "neutral",
}


@app.command()
def version() -> None:
    """Print package and contract version."""
    typer.echo(f"codesheriff-engine v0.1.0 (Contract: v{CONTRACT_VERSION})")


@app.command()
def fuse(
    evidence_path: Path = typer.Argument(..., help="JSON file holding a list of Evidence"),
    prior: float = typer.Option(None, help="Override the fitted base rate for this run"),
    threshold: float = typer.Option(None, help="Override the fitted alert threshold"),
) -> None:
    """Fuse one unit's evidence and show every witness's contribution to the posterior."""
    if not evidence_path.exists():
        typer.secho(f"Error: file not found at '{evidence_path}'", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1)

    try:
        raw = json.loads(evidence_path.read_text(encoding="utf-8"))
        evidence = [Evidence.model_validate(item) for item in raw]
    except Exception as exc:
        typer.secho(f"Error: could not parse evidence: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=1) from exc

    config = EngineConfig.load()
    prior_p = config.prior_probability if prior is None else prior
    alert_threshold = config.alert_threshold if threshold is None else threshold

    results = fuse_all_evidence(
        evidence, prior_p=prior_p, alert_threshold=alert_threshold, ratios=config.ratios
    )

    typer.secho(
        f"\nPROVISIONAL — ratios, prior ({prior_p}) and threshold ({alert_threshold}) are "
        "asserted, not fitted (D-010).",
        fg=typer.colors.YELLOW,
    )

    if not results:
        kinds = {ev.kind for ev in evidence}
        typer.secho(
            f"\nNo finding. {len(evidence)} statement(s), none of them a detection "
            f"({', '.join(sorted(k.value for k in kinds)) or 'nothing at all'}).",
            fg=typer.colors.GREEN,
        )
        typer.echo(
            "A unit nobody detected anything in produces evidence and no finding — there is "
            "no synthetic 'all agents abstained' key any more."
        )
        return

    for idx, result in enumerate(results, start=1):
        tag = "[ALERT]" if result.is_alert_worthy else "[below threshold]"
        colour = typer.colors.RED if result.is_alert_worthy else typer.colors.GREEN
        typer.secho(
            f"\n#{idx} {tag} {result.cwe}  P(vulnerable) = "
            f"{result.posterior_probability * 100:.1f}%",
            fg=colour,
            bold=True,
        )
        typer.echo(f"   finding_key : {result.finding_key}")
        typer.echo(f"   severity    : {result.severity}")
        typer.echo(f"\n   prior {prior_p:.4f}  (odds {prior_p / (1 - prior_p):.4f})")

        for contribution in result.contributions:
            typer.echo(
                f"     x {contribution.likelihood_ratio:>6.2f}  "
                f"{contribution.witness:<11} {_STANCE_TAG[contribution.stance]:<9} "
                f"{(contribution.cell.value if contribution.cell else 'abstention'):<16} "
                f"{contribution.note}"
            )

        typer.echo(f"   = {result.posterior_probability:.4f}\n")
        typer.echo("   Statements:")
        for ev in result.evidence_list:
            detail = (
                f"score {ev.raw_score:.2f}"
                if ev.kind is EvidenceKind.DETECTION
                else f"covers {', '.join(sorted(ev.covered_cwes))}"
                if ev.kind is EvidenceKind.SILENCE
                else f"reason {ev.reason}"
            )
            typer.echo(
                f"     - {ev.agent_id:<20} {ev.kind.value:<10} {detail:<28} {ev.explanation[:60]}"
            )


if __name__ == "__main__":
    app()
