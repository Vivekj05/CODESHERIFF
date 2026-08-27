"""Base retriever protocol interface."""

from __future__ import annotations

from typing import Any, Dict, List, Protocol
from semantic_agent.contracts import ChangeUnit


class Retriever(Protocol):
    """Protocol for retrieving extra contextual information for a ChangeUnit."""

    def retrieve(self, unit: ChangeUnit) -> List[Dict[str, Any]]:
        """Retrieve contextual snippets related to the given ChangeUnit."""
        ...
