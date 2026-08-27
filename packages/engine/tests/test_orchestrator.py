"""Unit and async integration tests for Orchestrator."""

import asyncio
from typing import List, Optional, Set
from codesheriff_engine.config import EngineConfig
from codesheriff_engine.contracts import ChangeUnit, Evidence
from codesheriff_engine.orchestrator import Orchestrator


class MockStaticAgent:
    def __init__(self, findings: List[Evidence]) -> None:
        self.id = "structural.taint"
        self.version = "0.1.0"
        self.findings = findings

    def analyze(self, unit: ChangeUnit, anchors: Optional[Set[str]] = None) -> List[Evidence]:
        return self.findings


class MockSemanticAgent:
    def __init__(self, findings: List[Evidence]) -> None:
        self.id = "semantic.hosted"
        self.version = "0.1.0"
        self.findings = findings
        self.received_anchors: Optional[Set[str]] = None

    def analyze(self, unit: ChangeUnit, anchors: Optional[Set[str]] = None) -> List[Evidence]:
        self.received_anchors = anchors
        return self.findings


class MockContextAgent:
    def __init__(self, findings: List[Evidence]) -> None:
        self.id = "context.rag"
        self.version = "0.1.0"
        self.findings = findings
        self.received_anchors: Optional[Set[str]] = None

    def analyze(self, unit: ChangeUnit, anchors: Optional[Set[str]] = None) -> List[Evidence]:
        self.received_anchors = anchors
        return self.findings


class CrashingAgent:
    def __init__(self) -> None:
        self.id = "crashing.agent"
        self.version = "0.1.0"

    def analyze(self, unit: ChangeUnit, anchors: Optional[Set[str]] = None) -> List[Evidence]:
        raise RuntimeError("Fatal hardware failure")


def test_orchestrator_two_phase_execution_and_anchor_passing(
    sample_vulnerable_unit: ChangeUnit,
    target_sqli_finding_key: str,
) -> None:
    static_ev = [
        Evidence(
            agent_id="structural.taint",
            agent_version="0.1.0",
            unit_id=sample_vulnerable_unit.unit_id,
            finding_key=target_sqli_finding_key,
            cwe="CWE-89",
            raw_score=0.90,
            explanation="Taint detected",
        )
    ]
    semantic_ev = [
        Evidence(
            agent_id="semantic.hosted",
            agent_version="0.1.0",
            unit_id=sample_vulnerable_unit.unit_id,
            finding_key=target_sqli_finding_key,
            cwe="CWE-89",
            raw_score=0.85,
            explanation="Intent is insecure SQL",
        )
    ]
    context_ev = [
        Evidence(
            agent_id="context.rag",
            agent_version="0.1.0",
            unit_id=sample_vulnerable_unit.unit_id,
            finding_key=target_sqli_finding_key,
            cwe="CWE-89",
            raw_score=0.80,
            explanation="Bypasses ORM pattern",
        )
    ]

    mock_static = MockStaticAgent(static_ev)
    mock_semantic = MockSemanticAgent(semantic_ev)
    mock_context = MockContextAgent(context_ev)

    orch = Orchestrator(
        config=EngineConfig(prior_probability=0.05, alert_threshold=0.70),
        static_agent=mock_static,
        semantic_agent=mock_semantic,
        context_agent=mock_context,
    )

    results = asyncio.run(orch.analyze_change_unit(sample_vulnerable_unit))

    # Phase 2 agents must have received the finding key from Phase 1
    assert mock_semantic.received_anchors == {target_sqli_finding_key}
    assert mock_context.received_anchors == {target_sqli_finding_key}

    # Verify fusion result
    assert len(results) == 1
    res = results[0]
    assert res.finding_key == target_sqli_finding_key
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

    # Orchestrator must never raise an exception
    results = asyncio.run(orch.analyze_change_unit(sample_vulnerable_unit))
    assert len(results) >= 1
    # All evidence in result are abstentions
    for ev in results[0].evidence_list:
        assert ev.abstained
        assert "orchestrator_caught_exception" in (ev.abstain_reason or "")
