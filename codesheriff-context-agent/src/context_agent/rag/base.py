"""Base protocol for vector text embedder."""

from __future__ import annotations

from typing import List, Protocol


class Embedder(Protocol):
    """Protocol for generating text embeddings."""

    def embed_text(self, text: str) -> List[float]:
        """Generate normalized floating-point embedding vector for given text."""
        ...
