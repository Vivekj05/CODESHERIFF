"""Tests for Hallucination Gate and Evidence mapping."""

from semantic_agent.contracts import ChangeUnit
from semantic_agent.mapping import HallucinationGate, map_finding_to_evidence
from semantic_agent.schema import LLMFinding


def test_hallucination_gate_valid(sample_unit: ChangeUnit) -> None:
    finding = LLMFinding(
        functional_intent="Fetch user details",
        untrusted_data_sources=["request.args.get('id')"],
        violated_safety_invariant="String formatted SQL query",
        cwe="CWE-89",
        title="SQL Injection",
        file="app/api/users.py",
        start_line=42,
        end_line=46,
        sink_expression="cursor.execute(q).fetchone()",
        severity="critical",
        rationale="Raw SQL execution",
        evidence_lines=[2, 3],
        exploitability="direct",
    )
    is_valid, reason = HallucinationGate.validate(finding, sample_unit)
    assert is_valid
    assert reason is None


def test_hallucination_gate_invalid_sink(sample_unit: ChangeUnit) -> None:
    finding = LLMFinding(
        functional_intent="Fetch user details",
        untrusted_data_sources=[],
        violated_safety_invariant="Missing check",
        cwe="CWE-89",
        title="SQL Injection",
        file="app/api/users.py",
        start_line=42,
        end_line=46,
        sink_expression="non_existent_function_call()",
        severity="critical",
        rationale="Hallucinated sink",
        evidence_lines=[2],
        exploitability="direct",
    )
    is_valid, reason = HallucinationGate.validate(finding, sample_unit)
    assert not is_valid
    assert "does not appear verbatim" in reason


def test_hallucination_gate_invalid_file(sample_unit: ChangeUnit) -> None:
    finding = LLMFinding(
        functional_intent="Fetch user details",
        untrusted_data_sources=[],
        violated_safety_invariant="Missing check",
        cwe="CWE-89",
        title="SQL Injection",
        file="completely/different/file.py",
        start_line=42,
        end_line=46,
        sink_expression="cursor.execute(q).fetchone()",
        severity="critical",
        rationale="Hallucinated file",
        evidence_lines=[2],
        exploitability="direct",
    )
    is_valid, reason = HallucinationGate.validate(finding, sample_unit)
    assert not is_valid
    assert "File path mismatch" in reason


def test_map_finding_to_evidence(sample_unit: ChangeUnit) -> None:
    finding = LLMFinding(
        functional_intent="Fetch user",
        untrusted_data_sources=["request"],
        violated_safety_invariant="Concatenated SQL",
        cwe="CWE-89",
        title="SQL Injection",
        file="app/api/users.py",
        start_line=42,
        end_line=46,
        sink_expression="cursor.execute(q).fetchone()",
        severity="critical",
        rationale="Raw SQL execution",
        evidence_lines=[2, 3],
        exploitability="direct",
    )
    evidence = map_finding_to_evidence(
        finding=finding,
        unit=sample_unit,
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        raw_score=1.0,
    )
    assert evidence.unit_id == sample_unit.unit_id
    assert evidence.cwe == "CWE-89"
    assert evidence.raw_score == 1.0
    assert not evidence.abstained
    assert len(evidence.finding_key) == 16
