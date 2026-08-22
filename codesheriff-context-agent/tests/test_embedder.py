"""Tests for LocalEmbedder."""

from context_agent.rag.embedder import LocalEmbedder


def test_local_embedder_dimension_and_norm() -> None:
    embedder = LocalEmbedder()
    text = "def process_payment(): return stripe_charge()"
    vector = embedder.embed_text(text)
    assert len(vector) == 384
    assert any(v != 0.0 for v in vector)
