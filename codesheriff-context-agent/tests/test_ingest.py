"""Tests for Hybrid PR Document ingestion."""

from pathlib import Path
from typing import Any, Dict
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.ingest import create_hybrid_pr_document, ingest_pr
from context_agent.rag.store import VectorStore


def test_create_hybrid_pr_document(sample_past_pr: Dict[str, Any]) -> None:
    doc = create_hybrid_pr_document(sample_past_pr)
    assert "# PR METADATA" in doc
    assert "pr-105" in doc
    assert "require_csrf_token" in doc


def test_ingest_pr(sample_past_pr: Dict[str, Any], tmp_path: Path) -> None:
    store = VectorStore(str(tmp_path / "test_chroma"))
    embedder = LocalEmbedder()

    pr_id = ingest_pr(sample_past_pr, store, embedder)
    assert pr_id == "pr-105"
    assert store.count() == 1
