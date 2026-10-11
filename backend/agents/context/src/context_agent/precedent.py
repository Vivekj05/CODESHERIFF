"""What this agent is handed, and by whom.

`context.rag` decides on **this repository's own precedent**, so it needs merged code to
read. It must not be the thing that fetches it. An agent may import `codesheriff_contracts`
and nothing else (`CLAUDE.md`, "Agent isolation"), and `lint-imports` fails the build for an
agent that reaches a database client — so the retrieval boundary is a Protocol here and the
implementation lives in `apps/worker`, which owns both the pgvector session and the embedding
model. `packages/storage/precedents.py` was written against exactly this arrangement.

Keeping the split has a second consequence that matters more than tidiness. The corpus
measurement injects a retriever built from a case's authored history, with no database and no
model download, and the agent it exercises is byte-for-byte the one production runs. An agent
that opened its own store could only ever be measured against a store someone stood up.

**Repository scoping is the implementation's job, and it is structural** (`AUDIT.md` 0.2). The
superseded store put every repository in one global Chroma collection and never recorded which
repository a document came from, so one repository's diffs could surface as another's review
context and no filter could be added without a full re-ingest. The retriever is constructed
against one repository and cannot be asked about another; there is no parameter to get wrong.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from codesheriff_contracts import ChangeUnit


class RetrievalUnavailableError(RuntimeError):
    """Precedent could not be consulted — the store, the embedding model, or the query.

    Distinct from "this repository has no precedent", and the distinction is the whole of
    D-005. A repository with no history is a **silence-adjacent abstention** the agent makes
    knowingly; a retriever that could not run is an abstention about the agent's own health.
    Collapsing them would let a broken embedding model report, forever and quietly, that
    every repository it was pointed at happened to have no relevant history.

    `AUDIT.md` 3.8 is what the collapse looked like: `sentence-transformers` was absent from
    the package's dependencies, so a normal install took an `except ImportError` branch and
    produced 384-dimensional **MD5 term hashes** — numbers with no semantic content, cosine
    near zero between paraphrases — with no log line and no abstention. An implementation of
    the Protocol below raises this instead.
    """


@dataclass(frozen=True)
class Precedent:
    """One merged excerpt this repository already accepted, and how close it was.

    Deliberately the same shape as `codesheriff_storage.PrecedentMatch` and as
    `codesheriff_corpus.PrecedentRecord`, minus the identifiers each of those needs for its
    own bookkeeping. Three representations of precedent that differed in shape would mean the
    agent measured on the corpus is not the agent that runs in production.

    Indexed **per symbol, not per pull request** (PROJECT_CONTEXT.md §5). `bge-small-en-v1.5`
    truncates at 512 tokens, so a PR-level document is silently cut and matches poorly against
    a function-level query.
    """

    pr_number: int
    file: str
    qualified_symbol: str
    accepted_src: str

    similarity: float = 1.0
    """Cosine similarity to the query, in [0, 1]. Reported rather than inverted distance,
    because a number a reader has to invert in their head is a number they will misread."""


@runtime_checkable
class PrecedentRetriever(Protocol):
    """The one thing this agent asks the outside world for.

    Implementations raise `RetrievalUnavailableError` on failure and return `[]` when the
    repository genuinely holds no relevant precedent. Returning `[]` for a failure is the bug
    this Protocol is documented to prevent.
    """

    def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
        """The nearest merged excerpts to `unit`, within `unit`'s repository only."""
        ...


class NoPrecedentRetriever:
    """The default, and it finds nothing.

    A `ContextAgent()` built with no retriever abstains on every unit under a reason that says
    so, which is the honest reading: nothing was consulted. The alternative default — an
    in-process store the agent fills itself — is how the superseded agent came to answer
    questions about a repository it had never seen.
    """

    def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
        return []
