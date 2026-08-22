"""Hybrid PR Document generator and vector store ingestion."""

from __future__ import annotations

from typing import Any, Dict
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.store import VectorStore


def create_hybrid_pr_document(pr_data: Dict[str, Any]) -> str:
    """Combine PR title, description, modified symbols, and code diff into one searchable document."""
    pr_id = pr_data.get("pr_id", "unknown-pr")
    title = pr_data.get("title", "")
    desc = pr_data.get("description", "")
    files = ", ".join(pr_data.get("files", []))
    symbols = ", ".join(pr_data.get("symbols", []))
    diff = pr_data.get("code_diff", "")

    return f"""# PR METADATA
PR_ID: {pr_id}
Title: {title}
Description: {desc}
Modified Files: {files}
Modified Symbols: {symbols}

# CODE DIFF SUMMARY
{diff}
"""


def ingest_pr(
    pr_data: Dict[str, Any],
    store: VectorStore,
    embedder: LocalEmbedder,
) -> str:
    """Generate hybrid document, embed text, and store into VectorStore."""
    pr_id = str(pr_data.get("pr_id", f"pr-{store.count() + 1}"))
    hybrid_doc = create_hybrid_pr_document(pr_data)
    vector = embedder.embed_text(hybrid_doc)

    metadata = {
        "pr_id": pr_id,
        "title": pr_data.get("title", ""),
        "files": ", ".join(pr_data.get("files", [])),
        "symbols": ", ".join(pr_data.get("symbols", [])),
    }

    store.add_pr(
        pr_id=pr_id,
        hybrid_document=hybrid_doc,
        embedding=vector,
        metadata=metadata,
    )
    return pr_id
