"""Shared helpers for the context witness.

Imported as `from .context_support import ...`, the relative form this repository already
uses for `apps/worker/tests/payloads.py`. Reaching these through `conftest` instead does not
survive a full-workspace run: two `conftest.py` files under one test root share a module
basename, so the import resolved to whichever pytest happened to load first.

The retriever here is a list, not a store. The agent's whole dependency on infrastructure is
one Protocol method, so exercising it needs no database, no embedding model and no network —
which is the property that lets the corpus measurement run the production `analyze()` path on
any machine.
"""

from __future__ import annotations

from codesheriff_contracts import ChangeUnit
from context_agent.precedent import Precedent, RetrievalUnavailableError


class ListRetriever:
    """Serves a fixed history, honouring `limit` the way a real one does."""

    def __init__(self, precedents: list[Precedent]) -> None:
        self.precedents = precedents
        self.calls: list[tuple[str, int]] = []

    def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
        self.calls.append((unit.unit_id, limit))
        return self.precedents[:limit]


class BrokenRetriever:
    """Fails the way a down store or an unloadable model does."""

    def __init__(self, message: str = "pgvector unreachable") -> None:
        self.message = message

    def retrieve(self, unit: ChangeUnit, limit: int) -> list[Precedent]:
        raise RetrievalUnavailableError(self.message)


def make_unit(
    post_src: str,
    *,
    symbol: str = "delete_note",
    file: str = "app/notes/views.py",
    enclosing_class: str | None = None,
    unit_id: str = "u1",
    language: str = "python",
) -> ChangeUnit:
    return ChangeUnit(
        unit_id=unit_id,
        repo="acme/app",
        language=language,
        file=file,
        symbol=symbol,
        enclosing_class=enclosing_class,
        post_src=post_src,
        base_sha="a" * 40,
        head_sha="b" * 40,
    )


def make_precedent(
    accepted_src: str,
    *,
    qualified_symbol: str,
    pr_number: int = 100,
    file: str = "app/notes/views.py",
    similarity: float = 0.9,
) -> Precedent:
    return Precedent(
        pr_number=pr_number,
        file=file,
        qualified_symbol=qualified_symbol,
        accepted_src=accepted_src,
        similarity=similarity,
    )


UNGUARDED_DELETE = (
    '@bp.delete("/notes/<int:note_id>")\n'
    "def delete_note(note_id):\n"
    "    note = Note.query.get_or_404(note_id)\n"
    "    note.delete()\n"
    "    return jsonify(deleted=note_id)\n"
)

GUARDED_DELETE = (
    '@bp.delete("/notes/<int:note_id>")\n'
    "@require_owner\n"
    "def delete_note(note_id):\n"
    "    note = Note.query.get_or_404(note_id)\n"
    "    note.delete()\n"
    "    return jsonify(deleted=note_id)\n"
)
