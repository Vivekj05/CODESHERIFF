"""Turning a symbol into a vector, or failing loudly.

`AUDIT.md` 3.8 is the whole reason this module has the shape it does. The superseded embedder
wrapped `SentenceTransformer` in `try/except ImportError` and, on the failing branch, produced
a 384-dimensional **MD5 term-hashing** vector: numbers with the right shape and no semantic
content, cosine near zero between paraphrases. `sentence-transformers` was not in the agent
package's dependencies, so that branch was the *default* path for a normal install. There was
no log line and no abstention. Retrieval returned noise, the agent reasoned over it, and
nothing anywhere said so.

So there is no fallback here. A missing model, a failed download and a wrong output dimension
each raise `RetrievalUnavailableError`, which `context.rag` records as an abstention naming the
failure — at a likelihood ratio of exactly 1.0, costing the posterior nothing and hiding from
nobody.

**One model, both directions.** `load_embedder` is what ingestion and querying both call. A
store written with one model and queried with another is a distance between two unrelated
vector spaces; it does not error, it just answers wrongly. `PrecedentChunk.embedding_model`
records which model wrote each row so a change of model is a migration rather than a surprise.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Protocol

from context_agent.precedent import RetrievalUnavailableError

logger = logging.getLogger(__name__)

EMBEDDING_MODEL_NAME = "BAAI/bge-small-en-v1.5"
"""384 dimensions, runs locally, no recurring cost (PROJECT_CONTEXT.md §4).

Must match `codesheriff_storage.models.EMBEDDING_DIM` and the `Vector(384)` column. Changing
it needs a migration and a re-ingest, not a cast.
"""

EMBEDDING_DIM = 384


class PrecedentEmbedder(Protocol):
    """Text to a normalised vector. Raises rather than returning something shaped right."""

    def embed(self, text: str) -> list[float]: ...


class LocalEmbedder:
    """`sentence-transformers` over a locally cached model.

    Loading is deferred to the first call and then held, because a Celery worker imports this
    module at start-up and a model download is not something to do while the process is still
    deciding whether it has work. The lock makes the first concurrent pair of calls load once;
    agents run in a thread pool, so that pair is the normal case rather than a rare one.
    """

    def __init__(self, model_name: str = EMBEDDING_MODEL_NAME) -> None:
        self.model_name = model_name
        self._model: Any | None = None
        self._lock = threading.Lock()

    def _load(self) -> Any:
        # Double-checked locking, read through a local. Re-testing `self._model` inside the
        # lock reads to a type checker as unreachable — it cannot model another thread
        # assigning the attribute between the two checks — and the local says plainly that the
        # second read is a fresh one.
        model = self._model
        if model is not None:
            return model

        with self._lock:
            model = self._model
            if model is not None:
                return model

            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:
                raise RetrievalUnavailableError(
                    "sentence-transformers is not installed, so precedent cannot be embedded. "
                    "There is deliberately no fallback: the superseded agent hashed text with "
                    "MD5 here and reported the result as an embedding (AUDIT.md 3.8)."
                ) from exc
            try:
                model = SentenceTransformer(self.model_name)
            except Exception as exc:
                raise RetrievalUnavailableError(
                    f"could not load the embedding model {self.model_name!r}: {exc}"
                ) from exc

            self._model = model
            logger.info("loaded embedding model %s", self.model_name)
        return model

    def embed(self, text: str) -> list[float]:
        model = self._load()
        try:
            vector = model.encode(text, normalize_embeddings=True)
        except Exception as exc:
            raise RetrievalUnavailableError(f"embedding failed: {exc}") from exc

        values = [float(x) for x in vector]
        if len(values) != EMBEDDING_DIM:
            # A model of the wrong size would be rejected by the Vector(384) column on write,
            # but on a *query* pgvector would simply refuse the comparison — and catching it
            # here names the cause instead of surfacing a driver error about operand types.
            raise RetrievalUnavailableError(
                f"{self.model_name} produced {len(values)} dimensions, expected {EMBEDDING_DIM}. "
                "The precedent column is fixed at 384; a different model needs a migration."
            )
        return values


_SHARED: LocalEmbedder | None = None
_SHARED_LOCK = threading.Lock()


def load_embedder(model_name: str = EMBEDDING_MODEL_NAME) -> PrecedentEmbedder:
    """The process-wide embedder.

    Shared because the model is hundreds of megabytes and every audit would otherwise pay to
    load it again. Held as a module global rather than on the Celery app so that the backfill
    command, which runs outside Celery entirely, gets the same instance discipline.
    """
    global _SHARED
    if _SHARED is not None and _SHARED.model_name == model_name:
        return _SHARED
    with _SHARED_LOCK:
        if _SHARED is None or _SHARED.model_name != model_name:
            _SHARED = LocalEmbedder(model_name)
    return _SHARED


def query_text(file: str, qualified_symbol: str, source: str) -> str:
    """The text a unit or an excerpt is embedded as.

    **Identical on both sides**, which is the only property that matters here: a stored chunk
    and the query it should match have to be rendered the same way, or the nearest neighbour is
    decided by formatting. It is a module-level function rather than a method on either side
    for exactly that reason.

    The symbol leads because it is the strongest signal of what the code is *for*, and
    `bge-small-en-v1.5` truncates at 512 tokens — what comes first survives.

    No PR title or description (D-014). They are attacker-controlled and absent from corpus
    cases, and embedding them would make a corpus run and a production run different runs. The
    superseded `rag/ingest.py` put both into every indexed document.
    """
    return f"{qualified_symbol}\n{file}\n\n{source}"
