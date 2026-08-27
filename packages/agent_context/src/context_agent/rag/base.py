"""Base protocol for vector text embedder."""

from __future__ import annotations

from typing import Protocol


class Embedder(Protocol):
    """Protocol for generating text embeddings."""

    def embed_text(self, text: str) -> list[float]:
        """Generate normalized floating-point embedding vector for given text."""
        ...
