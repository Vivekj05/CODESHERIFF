"""End-to-end tests for ContextAgent."""

from pathlib import Path
from typing import Any

from codesheriff_contracts import ChangeUnit, EvidenceKind
from context_agent.agent import ContextAgent
from context_agent.config import ContextConfig
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.ingest import ingest_pr
from context_agent.rag.store import VectorStore


def _agent(tmp_path: Path, past_pr: dict[str, Any]) -> ContextAgent:
    store = VectorStore(str(tmp_path / "store"))
    embedder = LocalEmbedder()
    ingest_pr(past_pr, store, embedder)
    cfg = ContextConfig(chroma_db_dir=str(tmp_path / "store"))
    return ContextAgent(config=cfg, embedder=embedder, store=store)


def test_context_agent_detects_bypass_without_being_told_where_to_look(
    sample_bypassing_unit: ChangeUnit, sample_past_pr: dict[str, Any], tmp_path: Path
) -> None:
    """The agent runs blind (D-008) and still emits under the shared key (D-012).

    It previously abstained with `no_anchor` unless handed the static agent's
    finding keys — and the static agent has no CWE-862 sink, so the anchor set could
    never contain this key and the agent contributed nothing, ever (AUDIT.md 1.5).
    """
    agent = _agent(tmp_path, sample_past_pr)

    ev_list = agent.analyze(sample_bypassing_unit)

    detections = [e for e in ev_list if e.kind is EvidenceKind.DETECTION]
    assert len(detections) == 1
    ev = detections[0]
    assert ev.cwe == "CWE-862"
    # The key is the one any agent derives for this unit and CWE — not a private one.
    assert ev.finding_key == sample_bypassing_unit.key_for("CWE-862")


def test_context_agent_is_silent_not_empty_when_nothing_regressed(
    sample_unit: ChangeUnit, sample_past_pr: dict[str, Any], tmp_path: Path
) -> None:
    """Ran and found nothing is SILENCE, and it declares what it could have found."""
    agent = _agent(tmp_path, sample_past_pr)

    ev_list = agent.analyze(sample_unit)

    assert ev_list, "returning [] makes 'looked, found nothing' indistinguishable from failure"
    assert all(e.kind is not EvidenceKind.DETECTION for e in ev_list)
    for ev in ev_list:
        if ev.kind is EvidenceKind.SILENCE:
            assert ev.covered_cwes, "SILENCE without covered_cwes suppresses other agents (D-006)"


def test_context_agent_never_raises(sample_unit: ChangeUnit) -> None:
    class FailingStore:
        def count(self) -> int:
            raise RuntimeError("Database connection failure")

    agent = ContextAgent(store=FailingStore())  # type: ignore[arg-type]
    ev_list = agent.analyze(sample_unit)

    assert len(ev_list) == 1
    assert ev_list[0].kind is EvidenceKind.ABSTENTION
    assert ev_list[0].reason == "runtime_error"
