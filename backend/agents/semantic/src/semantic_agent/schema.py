"""The structured output contract for one model response.

`cwe` used to be a free-form `str`, so any string the model emitted was upper-cased and shipped
into `Evidence.cwe` (`AUDIT.md` 3.10). The `Evidence` validator would have caught an out-of-scope
CWE eventually, but as a raised exception deep in the mapping rather than as one discarded finding —
so a single hallucinated CWE cost the whole sample.

Rejecting it here means a bad finding is dropped and the rest of the response survives, which is
what "drop, never relabel" requires in practice (D-021).

`start_line`/`end_line` are validated for internal consistency here; whether they fall inside the
*unit* is `HallucinationGate`'s job, because only the gate has the unit.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from codesheriff_contracts import IN_SCOPE_CWES


class LLMFinding(BaseModel):
    """One vulnerability the model claims to have found."""

    functional_intent: str = Field(..., max_length=400, description="Stage 1: what the code does.")
    untrusted_data_sources: list[str] = Field(
        default_factory=list,
        max_length=8,
        description="Stage 2: the expressions untrusted data arrives through.",
    )
    violated_safety_invariant: str = Field(
        ..., max_length=400, description="Stage 3: the guarantee that is missing."
    )
    cwe: str = Field(..., description="One of IN_SCOPE_CWES. Anything else is rejected.")
    title: str = Field(..., max_length=120)
    file: str
    start_line: int = Field(..., ge=1)
    end_line: int = Field(..., ge=1)
    sink_expression: str = Field(
        ..., min_length=1, max_length=500, description="Verbatim from post_src."
    )
    severity: Literal["critical", "high", "medium", "low"]
    rationale: str = Field(..., max_length=800)
    evidence_lines: list[int] = Field(default_factory=list, max_length=20)
    exploitability: Literal["direct", "conditional", "theoretical"] = "direct"

    @field_validator("cwe")
    @classmethod
    def _cwe_must_be_in_scope(cls, value: str) -> str:
        """`IN_SCOPE_CWES` is closed (§6). A model naming anything else is inventing scope."""
        normalised = value.strip().upper()
        if normalised not in IN_SCOPE_CWES:
            raise ValueError(
                f"{normalised!r} is outside IN_SCOPE_CWES; findings are dropped, never relabelled"
            )
        return normalised

    @model_validator(mode="after")
    def _lines_must_be_ordered(self) -> LLMFinding:
        if self.end_line < self.start_line:
            raise ValueError(f"end_line {self.end_line} precedes start_line {self.start_line}")
        return self


class LLMResponse(BaseModel):
    """Everything the model reported about one unit."""

    findings: list[LLMFinding] = Field(default_factory=list, max_length=5)
