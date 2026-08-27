"""End-to-end tests for ContextAgent."""

from pathlib import Path
from typing import Any, Dict
from context_agent.agent import ContextAgent
from context_agent.config import ContextConfig
from context_agent.contracts import ChangeUnit, finding_key
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.ingest import ingest_pr
from context_agent.rag.store import VectorStore


def test_context_agent_no_anchors_abstains(
    sample_bypassing_unit: ChangeUnit, sample_past_pr: Dict[str, Any], tmp_path: Path
) -> None:
    store = VectorStore(str(tmp_path / "store"))
    embedder = LocalEmbedder()
    ingest_pr(sample_past_pr, store, embedder)

    cfg = ContextConfig(chroma_db_dir=str(tmp_path / "store"))
    agent = ContextAgent(config=cfg, embedder=embedder, store=store)

    # Calling analyze without anchors
    ev_list = agent.analyze(sample_bypassing_unit, anchors=None)
    assert len(ev_list) == 1
    assert ev_list[0].abstained
    assert ev_list[0].abstain_reason == "no_anchor"


def test_context_agent_with_anchors_detects_bypass(
    sample_bypassing_unit: ChangeUnit, sample_past_pr: Dict[str, Any], tmp_path: Path
) -> None:
    store = VectorStore(str(tmp_path / "store"))
    embedder = LocalEmbedder()
    ingest_pr(sample_past_pr, store, embedder)

    cfg = ContextConfig(chroma_db_dir=str(tmp_path / "store"))
    agent = ContextAgent(config=cfg, embedder=embedder, store=store)

    target_key = finding_key("app/payment.py", "quick_payment", "CWE-862", "stripe_charge(request.json)")
    ev_list = agent.analyze(sample_bypassing_unit, anchors={target_key})

    assert len(ev_list) == 1
    ev = ev_list[0]
    assert not ev.abstained
    assert ev.finding_key == target_key
    assert ev.cwe == "CWE-862"


def test_context_agent_never_raises(sample_unit: ChangeUnit, tmp_path: Path) -> None:
    class FailingStore:
        def count(self):
            raise RuntimeError("Database connection failure")

    agent = ContextAgent(store=FailingStore())
    ev_list = agent.analyze(sample_unit, anchors={"some_key"})
    assert len(ev_list) == 1
    assert ev_list[0].abstained
    assert ev_list[0].abstain_reason == "runtime_error"
