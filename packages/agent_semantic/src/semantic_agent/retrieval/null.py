"""Null retriever implementation returning empty context."""

from __future__ import annotations

from typing import Any, Dict, List
from semantic_agent.contracts import ChangeUnit


class NullRetriever:
    """Default retriever returning empty context."""

    def retrieve(self, unit: ChangeUnit) -> List[Dict[str, Any]]:
        """Return empty list."""
        return []
