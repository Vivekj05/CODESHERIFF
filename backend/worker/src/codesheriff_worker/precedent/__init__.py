"""Precedent: writing this repository's merged history, and querying it for `context.rag`.

Everything the context agent is not allowed to know lives here. The agent may import
`codesheriff_contracts` and nothing else, so it declares a `PrecedentRetriever` Protocol and
this package supplies the implementation — the pgvector session, the embedding model, and the
GitHub client that fills the store. `lint-imports` fails the build if that boundary is crossed
from the other direction.

One embedding model serves both directions, deliberately. A query embedded by a different
model than the rows it is compared against is a cosine distance between two unrelated vector
spaces, which returns confident nonsense rather than an error.
"""

from __future__ import annotations

from codesheriff_worker.precedent.embedding import (
    EMBEDDING_MODEL_NAME,
    PrecedentEmbedder,
    load_embedder,
)
from codesheriff_worker.precedent.retriever import PgVectorPrecedentRetriever

__all__ = [
    "EMBEDDING_MODEL_NAME",
    "PgVectorPrecedentRetriever",
    "PrecedentEmbedder",
    "load_embedder",
]
