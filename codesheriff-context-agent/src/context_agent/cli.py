"""Command line interface for CodeSheriff RAG Context Agent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional
import typer

from context_agent import __version__
from context_agent.agent import ContextAgent
from context_agent.config import ContextConfig
from context_agent.contracts import ChangeUnit
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.ingest import ingest_pr
from context_agent.rag.store import VectorStore
from context_agent.retrieval.search import retrieve_similar_prs

app = typer.Typer(
    name="context-agent",
    help="CodeSheriff RAG Context Agent Security Reviewer CLI",
)


@app.command()
def run(
    unit_path: Path = typer.Argument(
        ...,
        help="Path to ChangeUnit JSON file",
        exists=True,
        readable=True,
    ),
    anchor: Optional[List[str]] = typer.Option(
        None,
        "--anchor",
        "-a",
        help="Finding key anchor ID (can be passed multiple times)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path for Evidence JSON array",
    ),
) -> None:
    """Analyze a ChangeUnit payload for cross-PR security regressions."""
    content = unit_path.read_text(encoding="utf-8")
    data = json.loads(content)
    unit = ChangeUnit.model_validate(data)

    agent = ContextAgent()
    anchors_set = set(anchor) if anchor else None
    evidence_list = agent.analyze(unit, anchors=anchors_set)

    out_data = [ev.model_dump() for ev in evidence_list]
    json_str = json.dumps(out_data, indent=2)

    if output:
        output.write_text(json_str, encoding="utf-8")
        typer.echo(f"Evidence written to {output}")
    else:
        typer.echo(json_str)


@app.command()
def ingest(
    pr_file: Path = typer.Argument(
        ...,
        help="Path to accepted PR metadata JSON file",
        exists=True,
        readable=True,
    ),
) -> None:
    """Ingest an accepted merged PR document into the vector store."""
    data = json.loads(pr_file.read_text(encoding="utf-8"))
    cfg = ContextConfig.load()
    embedder = LocalEmbedder(cfg.embedding_model)
    store = VectorStore(cfg.chroma_db_dir)

    pr_id = ingest_pr(data, store, embedder)
    typer.echo(f"Successfully ingested PR document '{pr_id}' into RAG vector store. Total count: {store.count()}")


@app.command()
def search(
    unit_path: Path = typer.Argument(
        ...,
        help="Path to ChangeUnit JSON file",
        exists=True,
        readable=True,
    ),
    top_k: int = typer.Option(3, "--top-k", "-k", help="Number of similar PRs to return"),
) -> None:
    """Search vector store for top-K past PRs similar to ChangeUnit."""
    content = unit_path.read_text(encoding="utf-8")
    data = json.loads(content)
    unit = ChangeUnit.model_validate(data)

    cfg = ContextConfig.load()
    embedder = LocalEmbedder(cfg.embedding_model)
    store = VectorStore(cfg.chroma_db_dir)

    res = retrieve_similar_prs(unit, store, embedder, top_k=top_k)
    typer.echo(json.dumps(res, indent=2))


@app.command()
def version() -> None:
    """Display Context Agent version and configuration."""
    cfg = ContextConfig.load()
    typer.echo(f"CodeSheriff RAG Context Agent v{__version__}")
    typer.echo(f"Agent ID: {cfg.agent_id}")
    typer.echo(f"ChromaDB Dir: {cfg.chroma_db_dir}")
    typer.echo(f"Embedding Model: {cfg.embedding_model}")
    typer.echo(f"Similarity Threshold: {cfg.similarity_threshold}")


if __name__ == "__main__":
    app()
