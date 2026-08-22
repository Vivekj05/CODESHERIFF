"""Persistent vector store manager wrapper."""

from __future__ import annotations

import json
import math
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


def cosine_similarity(vec1: List[float], vec2: List[float]) -> float:
    """Calculate cosine similarity between two vectors."""
    if not vec1 or not vec2 or len(vec1) != len(vec2):
        return 0.0
    dot = sum(a * b for a, b in zip(vec1, vec2))
    norm1 = math.sqrt(sum(a * a for a in vec1))
    norm2 = math.sqrt(sum(b * b for b in vec2))
    if norm1 == 0 or norm2 == 0:
        return 0.0
    return dot / (norm1 * norm2)


class VectorStore:
    """Persistent vector database store for accepted pull requests."""

    def __init__(self, storage_dir: str = "./.chroma_db") -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self._chroma_collection = None
        self._sqlite_path = self.storage_dir / "prs_store.db"

        try:
            import chromadb
            client = chromadb.PersistentClient(path=str(self.storage_dir))
            self._chroma_collection = client.get_or_create_collection(
                name="accepted_pull_requests",
                metadata={"hnsw:space": "cosine"},
            )
        except ImportError:
            self._init_sqlite()

    def _init_sqlite(self) -> None:
        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS prs (
                    id TEXT PRIMARY KEY,
                    document TEXT NOT NULL,
                    embedding TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def count(self) -> int:
        """Return total count of ingested PR documents."""
        if self._chroma_collection:
            return self._chroma_collection.count()
        with sqlite3.connect(self._sqlite_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM prs")
            row = cursor.fetchone()
            return row[0] if row else 0

    def add_pr(
        self,
        pr_id: str,
        hybrid_document: str,
        embedding: List[float],
        metadata: Dict[str, Any],
    ) -> None:
        """Store accepted PR document and vector embedding."""
        if self._chroma_collection:
            self._chroma_collection.add(
                ids=[pr_id],
                documents=[hybrid_document],
                embeddings=[embedding],
                metadatas=[metadata],
            )
            return

        with sqlite3.connect(self._sqlite_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO prs (id, document, embedding, metadata) VALUES (?, ?, ?, ?)",
                (pr_id, hybrid_document, json.dumps(embedding), json.dumps(metadata)),
            )
            conn.commit()

    def query_similar_prs(
        self, query_embedding: List[float], top_k: int = 3
    ) -> Dict[str, List[Any]]:
        """Query top-K similar PRs by cosine similarity."""
        if self._chroma_collection:
            res = self._chroma_collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
            )
            return res

        # SQLite fallback search
        records = []
        with sqlite3.connect(self._sqlite_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, document, embedding, metadata FROM prs")
            for row in cursor.fetchall():
                p_id, doc, emb_str, meta_str = row
                emb = json.loads(emb_str)
                meta = json.loads(meta_str)
                sim = cosine_similarity(query_embedding, emb)
                records.append({
                    "id": p_id,
                    "document": doc,
                    "metadata": meta,
                    "similarity": sim,
                    "distance": 1.0 - sim,
                })

        records.sort(key=lambda r: r["similarity"], reverse=True)
        top = records[:top_k]

        return {
            "ids": [[r["id"] for r in top]],
            "documents": [[r["document"] for r in top]],
            "metadatas": [[r["metadata"] for r in top]],
            "distances": [[r["distance"] for r in top]],
        }
