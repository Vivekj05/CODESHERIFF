"""Unit and async integration tests for Orchestrator."""

import asyncio
import inspect

from codesheriff_contracts import ChangeUnit, Evidence, EvidenceKind
from codesheriff_engine.config import EngineConfig
from codesheriff_engine.orchestrator import Orchestrator


class RecordingAgent:
    """An agent that records exactly what the orchestrator handed it."""

    def __init__(self, agent_id: str, findings: list[Evidence]) -> None:
        self.id = agent_id
        self.version = "0.1.0"
        self.findings = findings
        self.calls: list[tuple] = []

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        self.calls.append((unit.unit_id,))
        return self.findings


class CrashingAgent:
    def __init__(self) -> None:
        self.id = "crashing.agent"
        self.version = "0.1.0"

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        raise RuntimeError("Fatal hardware failure")


def _detection(agent_id: str, unit: ChangeUnit, key: str, score: float) -> Evidence:
    return Evidence.detection(
        agent_id=agent_id,
        agent_version="0.1.0",
        unit_id=unit.unit_id,
        finding_key=key,
        cwe="CWE-89",
        raw_score=score,
        explanation=f"{agent_id} reported SQL injection",
    )


def test_agents_receive_only_the_unit(
    sample_vulnerable_unit: ChangeUnit,
    target_sqli_finding_key: str,
) -> None:
    """No anchors are passed, and none can be (D-008).

    The orchestrator previously ran the static agent first and handed its finding
    keys to the other two, which could then only confirm what static had already
    found. Multiplying likelihood ratios across witnesses correlated that way does
    not produce a posterior probability.
    """
    key = target_sqli_finding_key
    static = RecordingAgent(
        "structural.taint", [_detection("structural.taint", sample_vulnerable_unit, key, 0.90)]
    )
    semantic = RecordingAgent(
        "semantic.hosted", [_detection("semantic.hosted", sample_vulnerable_unit, key, 0.85)]
    )
    context = RecordingAgent(
        "context.rag", [_detection("context.rag", sample_vulnerable_unit, key, 0.80)]
    )

    orch = Orchestrator(
        config=EngineConfig(prior_probability=0.05, alert_threshold=0.70),
        static_agent=static,
        semantic_agent=semantic,
        context_agent=context,
    )
    results = asyncio.run(orch.analyze_change_unit(sample_vulnerable_unit))

    # The contract is single-argument: there is nowhere to put an anchor.
    sig = inspect.signature(RecordingAgent.analyze)
    assert list(sig.parameters) == ["self", "unit"]
    for agent in (static, semantic, context):
        assert agent.calls == [(sample_vulnerable_unit.unit_id,)]

    assert len(results) == 1
    res = results[0]
    assert res.finding_key == key
    assert res.posterior_probability >= 0.85
    assert res.is_alert_worthy is True
    assert len(res.evidence_list) == 3


def test_orchestrator_handles_agent_crash_gracefully(
    sample_vulnerable_unit: ChangeUnit,
) -> None:
    orch = Orchestrator(
        config=EngineConfig(),
        static_agent=CrashingAgent(),
        semantic_agent=CrashingAgent(),
        context_agent=CrashingAgent(),
    )

    results = asyncio.run(orch.analyze_change_unit(sample_vulnerable_unit))
    assert len(results) >= 1
    for ev in results[0].evidence_list:
        assert ev.kind is EvidenceKind.ABSTENTION
        assert ev.reason == "orchestrator_caught_exception"
