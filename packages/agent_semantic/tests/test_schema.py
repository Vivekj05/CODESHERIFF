"""Tests for Pydantic schema validation."""

import pytest
from pydantic import ValidationError
from semantic_agent.schema import LLMFinding, LLMResponse


def test_valid_llm_finding() -> None:
    finding = LLMFinding(
        functional_intent="Execute database query",
        untrusted_data_sources=["request.args.get('id')"],
        violated_safety_invariant="Query parameters are concatenated into SQL string without escaping.",
        cwe="CWE-89",
        title="SQL Injection in get_user",
        file="app/api/users.py",
        start_line=42,
        end_line=46,
        sink_expression="cursor.execute(q).fetchone()",
        severity="high",
        rationale="Unsanitized user input is concatenated into raw SQL string.",
        evidence_lines=[2, 3],
        exploitability="direct",
    )
    assert finding.cwe == "CWE-89"
    assert finding.severity == "high"


def test_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        LLMFinding(
            functional_intent="Intent",
            violated_safety_invariant="Invariant",
            cwe="CWE-89",
            title="Title",
            file="app.py",
            start_line=1,
            end_line=5,
            sink_expression="sink()",
            severity="extreme",  # Invalid enum
            rationale="Rationale",
        )


def test_empty_llm_response() -> None:
    resp = LLMResponse(findings=[])
    assert len(resp.findings) == 0
