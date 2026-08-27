"""Tests for self-consistency finding aggregation."""

from semantic_agent.consistency import aggregate_self_consistency
from semantic_agent.contracts import ChangeUnit
from semantic_agent.schema import LLMFinding, LLMResponse


def test_aggregate_self_consistency(sample_unit: ChangeUnit) -> None:
    f1 = LLMFinding(
        functional_intent="Fetch user details",
        untrusted_data_sources=["request"],
        violated_safety_invariant="SQL injection",
        cwe="CWE-89",
        title="SQL Injection",
        file="app/api/users.py",
        start_line=42,
        end_line=46,
        sink_expression="cursor.execute(q).fetchone()",
        severity="medium",
        rationale="Short rationale",
        evidence_lines=[2],
        exploitability="direct",
    )

    f2 = LLMFinding(
        functional_intent="Fetch user details",
        untrusted_data_sources=["request"],
        violated_safety_invariant="SQL injection",
        cwe="CWE-89",
        title="SQL Injection",
        file="app/api/users.py",
        start_line=42,
        end_line=46,
        sink_expression="cursor.execute(q).fetchone()",
        severity="high",
        rationale="Much longer detailed rationale explaining the issue",
        evidence_lines=[3],
        exploitability="direct",
    )

    r1 = LLMResponse(findings=[f1])
    r2 = LLMResponse(findings=[f2])
    r3 = LLMResponse(findings=[])  # Sample 3 returned no findings

    ev_list = aggregate_self_consistency([r1, r2, r3], sample_unit, "semantic.hosted", "0.1.0")

    assert len(ev_list) == 1
    ev = ev_list[0]
    # 2 out of 3 samples matched
    assert ev.raw_score == round(2 / 3, 3)
    assert ev.cwe == "CWE-89"
