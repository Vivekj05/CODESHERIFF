"""Tests for LLMCache module."""

from pathlib import Path
from semantic_agent.llm.cache import LLMCache


def test_llm_cache(tmp_path: Path) -> None:
    db_file = tmp_path / "test_cache.db"
    cache = LLMCache(str(db_file))

    key = cache.compute_key("sys", "user", "model", "v1", 0.3, 100)
    assert cache.get(key) is None

    cache.set(key, '{"findings": []}')
    assert cache.get(key) == '{"findings": []}'
