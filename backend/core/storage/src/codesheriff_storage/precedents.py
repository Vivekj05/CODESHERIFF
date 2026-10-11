"""The pgvector precedent store: write merged-PR excerpts, retrieve by similarity.

Chapter 12 replaces the context agent's four substring tests with retrieval over this table. The
agent itself never sees any of it. `context.rag` may import `contracts` and nothing else, so it
receives a retriever satisfying a Protocol and the worker injects the implementation that lives
here — an agent that could open a session would be an agent that knows about infrastructure, and
`lint-imports` fails the build for it.

Distance is cosine, matching the normalised vectors `BAAI/bge-small-en-v1.5` produces.
`PrecedentMatch.similarity` is reported as `1 - distance` because that is what the finding page
shows, and a number a reader has to invert in their head is a number they will misread.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from codesheriff_storage.mapping import sha256_text
from codesheriff_storage.models import EMBEDDING_DIM, PrecedentChunk, PRPrecedent
from codesheriff_storage.redaction import redact_chunk


@dataclass(frozen=True)
class PrecedentMatch:
    """One retrieved precedent excerpt and how close it was."""

    chunk_id: uuid.UUID
    pr_number: int
    file: str
    qualified_symbol: str | None
    content: str
    similarity: float


def build_chunk(
    precedent_id: uuid.UUID,
    file: str,
    content: str,
    embedding: list[float],
    chunk_index: int = 0,
    qualified_symbol: str | None = None,
    embedding_model: str = "BAAI/bge-small-en-v1.5",
) -> PrecedentChunk:
    """One embedded excerpt, clipped to the excerpt budget before it becomes a row (D-027).

    The hash is taken of the clipped text, not the original: it identifies what is stored, and a
    hash of something the database does not hold cannot be checked against anything.
    """
    if len(embedding) != EMBEDDING_DIM:
        raise ValueError(
            f"embedding has {len(embedding)} dimensions, expected {EMBEDDING_DIM}. The column is "
            f"fixed to {EMBEDDING_DIM}-dim BAAI/bge-small-en-v1.5 vectors; a different model needs "
            f"a migration, not a cast."
        )
    clipped = redact_chunk(content)
    return PrecedentChunk(
        precedent_id=precedent_id,
        file=file,
        qualified_symbol=qualified_symbol,
        chunk_index=chunk_index,
        content=clipped,
        content_sha256=sha256_text(clipped),
        embedding=embedding,
        embedding_model=embedding_model,
    )


def search_precedents(
    session: Session,
    repository_id: int,
    embedding: list[float],
    limit: int = 5,
    min_similarity: float | None = None,
) -> list[PrecedentMatch]:
    """Nearest precedent excerpts within one repository.

    Scoped to `repository_id` deliberately. The context agent's claim is about *this* repository's
    own precedent; precedent borrowed from another repository would be a different agent making a
    different argument, and its failure mode — a repository with no history — would stop being
    visible.

    `min_similarity` defaults to None, meaning no floor: this returns the nearest `limit` chunks and
    reports how close each one was. Deciding what is close enough to count as precedent is the
    agent's judgement in Chapter 12, and eventually a fitted number — not a default buried in a
    query helper. A floor here would silently return fewer rows than `limit` and read as "the
    repository has no precedent", which is a different claim entirely.
    """
    if len(embedding) != EMBEDDING_DIM:
        raise ValueError(f"query embedding must be {EMBEDDING_DIM}-dim, got {len(embedding)}")

    distance = PrecedentChunk.embedding.cosine_distance(embedding)
    stmt = (
        select(PrecedentChunk, PRPrecedent.pr_number, distance.label("distance"))
        .join(PRPrecedent, PrecedentChunk.precedent_id == PRPrecedent.id)
        .where(PRPrecedent.repository_id == repository_id)
        .order_by(distance)
        .limit(limit)
    )

    matches: list[PrecedentMatch] = []
    for chunk, pr_number, dist in session.execute(stmt).all():
        similarity = 1.0 - float(dist)
        if min_similarity is not None and similarity < min_similarity:
            continue
        matches.append(
            PrecedentMatch(
                chunk_id=chunk.id,
                pr_number=pr_number,
                file=chunk.file,
                qualified_symbol=chunk.qualified_symbol,
                content=chunk.content,
                similarity=similarity,
            )
        )
    return matches
