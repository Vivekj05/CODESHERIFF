"""Tests for VectorStore."""

from pathlib import Path
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.store import VectorStore


def test_vector_store_add_and_query(tmp_path: Path) -> None:
    store = VectorStore(str(tmp_path / "test_chroma"))
    embedder = LocalEmbedder()

    assert store.count() == 0

    doc1 = "# PR METADATA\nPR_ID: pr-101\nTitle: Add CSRF wrapper"
    vec1 = embedder.embed_text(doc1)
    store.add_pr("pr-101", doc1, vec1, {"title": "Add CSRF wrapper"})

    assert store.count() == 1

    results = store.query_similar_prs(vec1, top_k=1)
    assert len(results["ids"][0]) == 1
    assert results["ids"][0][0] == "pr-101"
