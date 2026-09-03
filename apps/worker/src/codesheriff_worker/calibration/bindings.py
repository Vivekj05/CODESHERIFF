"""Per-case dependencies, bound to agents that are loaded exactly once.

The harness runs the **production** loader: `load_agents(deps=...)` fills the same four slots
`apps/worker` fills for a real audit, and `analyse_unit` runs them the same way. That is not
tidiness, it is the whole validity of the measurement — a ratio fitted against a differently
assembled agent describes an object production never builds.

But two of the four dependencies are per case. `context.rag` needs *this* case's authored
history, and `semantic.hosted` needs *this* case's recorded model responses. Reloading the
agents for every case would rebuild the runtime sandbox each time, and compiling a 26 MB
CPython module 76 times is minutes of work to prove nothing.

So the dependency objects are loaded once and **rebound** between cases. `bind(case)` swaps
what they answer with; the agents holding them never change. Units are analysed one at a time
(`AUDIT.md` 4.5), so the four agents that run concurrently within a unit all see the same
binding, and there is no window in which one of them reads another case's history.
"""

from __future__ import annotations

import math
import re
from typing import Protocol

from codesheriff_contracts import ChangeUnit
from codesheriff_corpus.models import CorpusCase
from context_agent.precedent import Precedent

_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN.findall(text)}


def _cosine_ish(left: set[str], right: set[str]) -> float:
    """Token-set cosine. Deterministic, dependency-free, and monotone in overlap.

    A stand-in for the embedding model's ordering, not an imitation of it. It has to agree with
    a real embedder on the only thing this measurement depends on — that a merged sibling in
    the same module ranks above an unrelated one — and it does, because those excerpts share
    identifiers. What is therefore *not* measured is pgvector's own nearest-neighbour ordering;
    that needs a populated store and belongs with the deployment, not with the fit.
    """
    if not left or not right:
        return 0.0
    return len(left & right) / math.sqrt(len(left) * len(right))


class Bindable(Protocol):
    """Anything the runner rebinds between cases."""

    def bind(self, case: CorpusCase) -> None: ...


class CaseBoundRetriever:
    """`PrecedentRetriever` over the currently bound case's authored history.

    No database, no model download, no network — the same discipline the semantic agent's
    cassettes follow (D-068), for the same reason: the measurement has to run identically on
    every machine and in CI, or the number it produces is about the machine.
    """

    def __init__(self) -> None:
        self._case: CorpusCase | None = None

    def bind(self, case: CorpusCase) -> None:
        self._case = case

    def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
        if self._case is None:
            return []
        query = _tokens(f"{unit.qualified_symbol} {unit.file} {unit.post_src}")
        scored = [
            Precedent(
                pr_number=record.pr_number,
                file=record.file,
                qualified_symbol=record.qualified_symbol,
                accepted_src=record.accepted_src,
                similarity=_cosine_ish(
                    query,
                    _tokens(f"{record.qualified_symbol} {record.file} {record.accepted_src}"),
                ),
            )
            for record in self._case.precedent
        ]
        return sorted(scored, key=lambda p: -p.similarity)[:limit]
