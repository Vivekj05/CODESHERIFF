"""Fixture retriever reading neighbours and local snippets."""

from __future__ import annotations

from typing import Any

from codesheriff_contracts import ChangeUnit


class FixtureRetriever:
    """Fixture retriever utilizing neighbours from unit payload."""

    def retrieve(self, unit: ChangeUnit) -> list[dict[str, Any]]:
        """Return unit neighbours."""
        return list(unit.neighbours)
