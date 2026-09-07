"""That the label boundary is still declared.

`lint-imports` enforces that no agent imports `codesheriff_corpus`. It cannot notice
the contract being deleted — with the contract gone it simply passes, which is the
exact shape of the failure AUDIT.md 4.8 records: a check that was defeated by editing
the thing it checked against rather than the thing it protected.

This asserts the declaration exists. It does not replace `lint-imports`; it removes
the way to disable it quietly.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

AGENT_PACKAGES = {"static_agent", "semantic_agent", "context_agent", "agent_runtime"}


def _root_pyproject() -> dict[str, Any]:
    root = Path(__file__).resolve().parents[3] / "pyproject.toml"
    assert root.is_file(), f"expected the workspace root at {root}"
    return tomllib.loads(root.read_text(encoding="utf-8"))


def _contracts() -> list[dict[str, Any]]:
    return _root_pyproject()["tool"]["importlinter"]["contracts"]


def test_corpus_is_graphed() -> None:
    """A root package import-linter does not graph is a package it cannot police."""
    assert "codesheriff_corpus" in _root_pyproject()["tool"]["importlinter"]["root_packages"]


def test_no_agent_may_import_the_corpus() -> None:
    """An agent that can read `label` is being told the answer, not measured."""
    forbidding = [
        c
        for c in _contracts()
        if c.get("type") == "forbidden" and "codesheriff_corpus" in c.get("forbidden_modules", [])
    ]
    assert forbidding, "no contract forbids importing codesheriff_corpus (D-045)"

    guarded: set[str] = set()
    for contract in forbidding:
        guarded |= set(contract.get("source_modules", []))
    assert guarded >= AGENT_PACKAGES, f"agents left unguarded: {sorted(AGENT_PACKAGES - guarded)}"


def test_the_corpus_cannot_reach_the_database() -> None:
    """Ground truth is files on disk. A corpus that could query Postgres would make
    `corpus_hash` a claim about one machine's database (D-025)."""
    forbidden = next(
        c
        for c in _contracts()
        if c.get("type") == "forbidden" and "codesheriff_corpus" in c.get("source_modules", [])
    )
    assert "sqlalchemy" in forbidden["forbidden_modules"]
    assert "codesheriff_storage" in forbidden["forbidden_modules"]
