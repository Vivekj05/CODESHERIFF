"""Pydantic schema for LLM structured output response."""

from __future__ import annotations

from typing import List, Literal
from pydantic import BaseModel, Field


class LLMFinding(BaseModel):
    """Vulnerability finding output by LLM security analyzer."""

    functional_intent: str = Field(
        ...,
        max_length=200,
        description="What the developer's code is attempting to accomplish.",
    )
    untrusted_data_sources: List[str] = Field(
        default_factory=list,
        description="Inputs coming from untrusted boundaries (HTTP, params, files, etc.).",
    )
    violated_safety_invariant: str = Field(
        ...,
        max_length=300,
        description="Security assumption missing or broken in this intent.",
    )
    cwe: str = Field(
        ...,
        description="Exact CWE ID, e.g. CWE-78, CWE-89, CWE-22, CWE-639",
    )
    title: str = Field(..., max_length=80)
    file: str
    start_line: int
    end_line: int
    sink_expression: str = Field(
        ...,
        description="Verbatim code expression where flaw manifests",
    )
    severity: Literal["critical", "high", "medium", "low"]
    rationale: str = Field(..., max_length=400)
    evidence_lines: List[int] = Field(default_factory=list)
    exploitability: Literal["direct", "conditional", "theoretical"] = Field(
        default="direct"
    )


class LLMResponse(BaseModel):
    """Root LLM output container."""

    findings: List[LLMFinding] = Field(default_factory=list, max_length=5)
