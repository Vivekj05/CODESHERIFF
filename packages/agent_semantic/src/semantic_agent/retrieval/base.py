"""Base retriever protocol interface."""

from __future__ import annotations

from typing import Any, Protocol

from codesheriff_contracts import ChangeUnit


class Retriever(Protocol):
    """Protocol for retrieving extra contextual information for a ChangeUnit."""

    def retrieve(self, unit: ChangeUnit) -> list[dict[str, Any]]:
        """Retrieve contextual snippets related to the given ChangeUnit."""
        ...
