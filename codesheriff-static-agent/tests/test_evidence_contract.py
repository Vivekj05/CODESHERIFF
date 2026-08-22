"""Tests verifying Evidence contracts produced by StaticAgent."""

from static_agent.agent import StaticAgent
from static_agent.contracts import ChangeUnit, Evidence


def test_sample_unit_vulnerable_detection(sample_unit: ChangeUnit) -> None:
    agent = StaticAgent()
    evidence_list = agent.analyze(sample_unit)

    assert isinstance(evidence_list, list)
    assert len(evidence_list) > 0
    
    first = evidence_list[0]
    assert isinstance(first, Evidence)
    assert not first.abstained
    assert first.cwe == "CWE-89"
    assert first.raw_score > 0.0
    assert len(first.artifacts) > 0
    assert first.artifacts[0].artifact_type == "taint_path"


def test_sample_unit_safe_twin_zero_findings(sample_unit_safe: ChangeUnit) -> None:
    agent = StaticAgent()
    evidence_list = agent.analyze(sample_unit_safe)

    # Safe twin must produce 0 findings (empty list or abstention)
    findings = [e for e in evidence_list if not e.abstained]
    assert len(findings) == 0, f"Expected 0 findings on safe twin, got {len(findings)}"
