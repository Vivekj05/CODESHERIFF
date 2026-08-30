"""Fixtures for the context witness.

The helper classes and sample sources live in `context_support`, imported by test modules as
`from .context_support import ...` — the relative form this repository already uses for
`apps/worker/tests/payloads.py`, and the one that works under `--import-mode=importlib`. A
plain `from context_support import ...` resolved by whichever directory pytest happened to put
on `sys.path` first, which worked when this package was run alone and broke the moment the
whole workspace was collected in one pass. This file cannot use the relative form, so it
builds its records directly.
"""

from __future__ import annotations

import pytest

from context_agent.precedent import Precedent

GET_NOTE = (
    '@bp.get("/notes/<int:note_id>")\n'
    "@require_owner\n"
    "def get_note(note_id):\n"
    "    note = Note.query.get_or_404(note_id)\n"
    "    return jsonify(note.as_dict())\n"
)

UPDATE_NOTE = (
    '@bp.patch("/notes/<int:note_id>")\n'
    "@require_owner\n"
    "def update_note(note_id):\n"
    "    note = Note.query.get_or_404(note_id)\n"
    "    note.save()\n"
    "    return jsonify(note.as_dict())\n"
)


@pytest.fixture
def guarded_history() -> list[Precedent]:
    """Two merged siblings that both carry `@require_owner` — a convention, not a habit."""
    return [
        Precedent(
            pr_number=141,
            file="app/notes/views.py",
            qualified_symbol="get_note",
            accepted_src=GET_NOTE,
            similarity=0.9,
        ),
        Precedent(
            pr_number=152,
            file="app/notes/views.py",
            qualified_symbol="update_note",
            accepted_src=UPDATE_NOTE,
            similarity=0.9,
        ),
    ]
