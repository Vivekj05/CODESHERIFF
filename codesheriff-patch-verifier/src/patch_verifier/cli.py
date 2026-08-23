"""Typer CLI interface for Patch & Verifier Agent."""

import json
from pathlib import Path
import typer
from patch_verifier import __version__
from patch_verifier.contracts import ChangeUnit, Evidence
from patch_verifier.patch.generator import LLMPatchGenerator
from patch_verifier.reporter.github_comment import format_pr_comment
from patch_verifier.verifier.engine import SimplifiedVerifier

app = typer.Typer(
    name="patch-verifier",
    help="CodeSheriff Patch Generator and Verifier Agent CLI",
    add_completion=False,
)


@app.command(name="generate")
def generate(
    unit_file: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to ChangeUnit JSON payload",
    )
) -> None:
    """Generate and verify an automated security patch for ChangeUnit payload."""
    try:
        data = json.loads(unit_file.read_text(encoding="utf-8"))
        unit = ChangeUnit.model_validate(data)
    except Exception as e:
        typer.secho(f"Error loading ChangeUnit JSON: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    evidence = Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id=unit.unit_id,
        finding_key="demo_finding",
        cwe="CWE-89",
        raw_score=0.9,
        confidence=0.95,
        explanation="SQL Injection vulnerability detected in query construction",
    )

    generator = LLMPatchGenerator()
    patch_diff = generator.generate_patch(unit, evidence)

    verifier = SimplifiedVerifier()
    v_res = verifier.verify_patch(unit, patch_diff)

    comment = format_pr_comment(
        unit=unit,
        posterior_prob=0.92,
        disagreement_index=0.015,
        verdict="VULNERABLE",
        evidence_list=[evidence],
        patch_diff=patch_diff if v_res.verified else None,
        verified=v_res.verified,
    )

    out = {
        "unit_id": unit.unit_id,
        "patch_diff": patch_diff,
        "verified": v_res.verified,
        "verification_explanation": v_res.explanation,
        "pr_comment_markdown": comment,
    }
    typer.echo(json.dumps(out, indent=2))


@app.command(name="health")
def health() -> None:
    """Print agent health status."""
    typer.echo(json.dumps({"status": "ok", "agent_id": "patch_verifier", "version": __version__}))


@app.command(name="version")
def version() -> None:
    """Print agent version."""
    typer.echo(f"patch-verifier v{__version__}")


if __name__ == "__main__":
    app()
