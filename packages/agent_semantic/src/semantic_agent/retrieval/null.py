"""Null retriever implementation returning empty context."""

from __future__ import annotations

from typing import Any

from codesheriff_contracts import ChangeUnit


class NullRetriever:
    """Default retriever returning empty context."""

    def retrieve(self, unit: ChangeUnit) -> list[dict[str, Any]]:
        """Return empty list."""
        return []
