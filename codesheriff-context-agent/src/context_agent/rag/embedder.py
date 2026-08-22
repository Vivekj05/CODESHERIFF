"""Local 384-dimensional vector embedder."""

from __future__ import annotations

import hashlib
import math
from typing import List


class LocalEmbedder:
    """Generates 384-dimensional normalized vector embeddings locally."""

    def __init__(self, model_name: str = "BAAI/bge-small-en-v1.5") -> None:
        self.model_name = model_name
        self._model = None

        try:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(model_name)
        except ImportError:
            self._model = None

    def embed_text(self, text: str) -> List[float]:
        """Generate normalized 384-dimensional embedding vector."""
        if self._model:
            emb = self._model.encode(text, normalize_embeddings=True)
            return list(map(float, emb))

        # Deterministic 384-dim normalized term-hashing vector fallback
        dim = 384
        vec = [0.0] * dim
        tokens = text.lower().split()
        if not tokens:
            return vec

        for token in tokens:
            h = int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16)
            idx = h % dim
            val = (h % 100) / 100.0 - 0.5
            vec[idx] += val

        norm = math.sqrt(sum(x * x for x in vec))
        if norm > 0:
            vec = [x / norm for x in vec]

        return vec
