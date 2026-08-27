"""Tests for Typer CLI commands in Context Agent."""

from pathlib import Path
from typer.testing import CliRunner
from context_agent.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "CodeSheriff RAG Context Agent" in result.stdout


def test_cli_ingest_and_run(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("CHROMA_DB_DIR", str(tmp_path / "cli_chroma"))

    past_pr_file = Path(__file__).parent / "fixtures" / "sample_past_pr.json"
    ingest_res = runner.invoke(app, ["ingest", str(past_pr_file)])
    assert ingest_res.exit_code == 0
    assert "Successfully ingested" in ingest_res.stdout

    bypassing_file = Path(__file__).parent / "fixtures" / "sample_bypassing_unit.json"
    search_res = runner.invoke(app, ["search", str(bypassing_file)])
    assert search_res.exit_code == 0
    assert "pr-105" in search_res.stdout

    run_res = runner.invoke(app, ["run", str(bypassing_file)])
    assert run_res.exit_code == 0
    assert "no_anchor" in run_res.stdout
