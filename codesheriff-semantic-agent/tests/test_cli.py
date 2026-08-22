"""Tests for Typer CLI commands."""

from pathlib import Path
from typer.testing import CliRunner
from semantic_agent.cli import app

runner = CliRunner()


def test_cli_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "CodeSheriff Semantic Agent" in result.stdout


def test_cli_run_file(tmp_path: Path, monkeypatch) -> None:
    # Set isolated cache path in env so cache does not persist between test runs
    monkeypatch.setenv("LLM_CACHE_PATH", str(tmp_path / "cli_cache.db"))
    sample_file = Path(__file__).parent / "fixtures" / "sample_unit.json"
    result = runner.invoke(app, ["run", str(sample_file)])
    assert result.exit_code == 0
    assert "demo-001" in result.stdout
