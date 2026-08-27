"""Fixture retriever reading neighbours and local snippets."""

from __future__ import annotations

from typing import Any, Dict, List
from semantic_agent.contracts import ChangeUnit


class FixtureRetriever:
    """Fixture retriever utilizing neighbours from unit payload."""

    def retrieve(self, unit: ChangeUnit) -> List[Dict[str, Any]]:
        """Return unit neighbours."""
        return list(unit.neighbours)
