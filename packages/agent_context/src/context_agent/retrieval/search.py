"""Similarity search for retrieving top-K past PRs."""

from __future__ import annotations

from typing import Any, Dict, List
from context_agent.contracts import ChangeUnit
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.store import VectorStore


def retrieve_similar_prs(
    unit: ChangeUnit,
    store: VectorStore,
    embedder: LocalEmbedder,
    top_k: int = 3,
) -> Dict[str, List[Any]]:
    """Generate vector embedding of new ChangeUnit and query vector store for top-K past PRs."""
    query_text = (
        f"File: {unit.file}\n"
        f"Symbol: {unit.symbol or 'N/A'}\n"
        f"Pre code:\n{unit.pre_src}\n"
        f"Post code:\n{unit.post_src}\n"
    )
    vector = embedder.embed_text(query_text)
    return store.query_similar_prs(vector, top_k=top_k)
