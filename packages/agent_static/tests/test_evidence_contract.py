"""Tests verifying Evidence contracts produced by StaticAgent."""

from codesheriff_contracts import ChangeUnit, Evidence, EvidenceKind
from static_agent.agent import StaticAgent


def test_sample_unit_vulnerable_detection(sample_unit: ChangeUnit) -> None:
    agent = StaticAgent()
    evidence_list = agent.analyze(sample_unit)

    assert isinstance(evidence_list, list)
    detections = [e for e in evidence_list if e.kind is EvidenceKind.DETECTION]
    assert detections

    first = detections[0]
    assert isinstance(first, Evidence)
    assert first.cwe == "CWE-89"
    assert first.raw_score > 0.0
    assert first.finding_key == sample_unit.key_for("CWE-89")
    assert len(first.artifacts) > 0
    assert first.artifacts[0].artifact_type == "taint_path"


def test_sample_unit_safe_twin_zero_findings(sample_unit_safe: ChangeUnit) -> None:
    agent = StaticAgent()
    evidence_list = agent.analyze(sample_unit_safe)

    findings = [e for e in evidence_list if e.kind is EvidenceKind.DETECTION]
    assert len(findings) == 0, f"Expected 0 findings on safe twin, got {len(findings)}"

    # And it must SAY it looked. An empty list would be indistinguishable from the
    # agent having crashed, and a safe twin that reads as a crash teaches the
    # calibration nothing (D-005).
    assert any(e.kind is EvidenceKind.SILENCE for e in evidence_list)
