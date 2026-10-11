"""The `PrecedentRetriever` the context agent actually gets in production.

**Cross-repository retrieval is impossible here, structurally.** `repository_id` is bound at
construction and there is no parameter, argument or code path that can name another
repository; `search_precedents` filters on it in SQL. That is the fix for `AUDIT.md` 0.2,
where every repository shared one global Chroma collection, `unit.repo` was never even stored
in metadata, and one repository's diffs could surface as another's review context. A filter
that has to be passed correctly is a filter that will eventually be passed wrongly.

`unit.repo` is deliberately *not* consulted. It is a string on an object the agent was handed;
the binding here comes from the audit's own repository row.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session, sessionmaker

from codesheriff_contracts import ChangeUnit
from codesheriff_storage.precedents import search_precedents
from codesheriff_worker.precedent.embedding import PrecedentEmbedder, query_text
from context_agent.precedent import Precedent, RetrievalUnavailableError

logger = logging.getLogger(__name__)


class PgVectorPrecedentRetriever:
    """Nearest merged excerpts within one repository, embedded by the model that wrote them.

    Opens its **own short-lived session** per call rather than borrowing the audit's. Agents
    run concurrently in a thread pool (`analysis.py`), a SQLAlchemy `Session` is not
    thread-safe, and the audit's session is mid-transaction with unflushed evidence rows on it.
    Sharing it would make this agent's reads interleave with another thread's writes — which
    fails rarely, unreproducibly, and in the middle of an audit.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        repository_id: int,
        embedder: PrecedentEmbedder,
    ) -> None:
        self._session_factory = session_factory
        self._repository_id = repository_id
        self._embedder = embedder

    def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
        """The `limit` nearest excerpts, or raise if precedent could not be consulted.

        An empty list means this repository holds no precedent — a real answer the agent
        reports as an abstention naming that. Every failure raises instead. Returning `[]` on a
        failure is the exact collapse D-005 and `AUDIT.md` 3.8 are about: a broken store would
        report, quietly and forever, that every repository it was pointed at was simply new.
        """
        embedding = self._embedder.embed(
            query_text(unit.file, unit.qualified_symbol, unit.post_src)
        )

        try:
            with self._session_factory() as session:
                matches = search_precedents(
                    session,
                    repository_id=self._repository_id,
                    embedding=embedding,
                    limit=limit,
                )
        except Exception as exc:
            logger.exception("precedent lookup failed for repository %s", self._repository_id)
            raise RetrievalUnavailableError(f"precedent store unavailable: {exc}") from exc

        return [
            Precedent(
                pr_number=match.pr_number,
                file=match.file,
                # The column is nullable; a chunk with no symbol cannot establish a convention
                # *about* a symbol, so it is named after its file rather than dropped — the
                # same-symbol rule will not match it and the sibling rule needs two anyway.
                qualified_symbol=match.qualified_symbol or match.file,
                accepted_src=match.content,
                similarity=match.similarity,
            )
            for match in matches
        ]
