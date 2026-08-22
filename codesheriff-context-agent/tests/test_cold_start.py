"""Tests for Cold Start (PR #1) handling."""

from pathlib import Path
from context_agent.agent import ContextAgent
from context_agent.config import ContextConfig
from context_agent.contracts import ChangeUnit
from context_agent.rag.store import VectorStore


def test_cold_start_empty_store_abstains(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    store = VectorStore(str(tmp_path / "empty_store"))
    cfg = ContextConfig(chroma_db_dir=str(tmp_path / "empty_store"))
    agent = ContextAgent(config=cfg, store=store)

    ev_list = agent.analyze(sample_unit)
    assert len(ev_list) == 1
    assert ev_list[0].abstained
    assert ev_list[0].abstain_reason == "no_historical_prs"
