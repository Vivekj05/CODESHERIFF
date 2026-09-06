"""Hallucination Gate and LLMFinding to Evidence mapper."""

from __future__ import annotations

import logging

from codesheriff_contracts import IN_SCOPE_CWES, Artifact, ChangeUnit, Evidence
from semantic_agent.schema import LLMFinding

logger = logging.getLogger(__name__)


class HallucinationGate:
    """Hard rejection gate preventing hallucinated findings from entering Evidence contracts."""

    @staticmethod
    def validate(finding: LLMFinding, unit: ChangeUnit) -> tuple[bool, str | None]:
        """Validate an LLMFinding against the ChangeUnit.

        Returns (is_valid, rejection_reason).
        """
        # 1. CWE scope check. IN_SCOPE_CWES is closed (PROJECT_CONTEXT.md §6); a model
        #    naming anything outside it is inventing scope, not reporting a finding.
        cwe = finding.cwe.strip().upper()
        if cwe not in IN_SCOPE_CWES:
            return False, f"CWE {cwe!r} is outside IN_SCOPE_CWES"

        # 2. File path validation — exact, not basename. Matching on basename let a
        #    finding about `app/models/user.py` be accepted against `tests/user.py`.
        if finding.file.strip() != unit.file.strip():
            return False, (
                f"File path mismatch: finding.file='{finding.file}' vs unit.file='{unit.file}'"
            )

        # 3. Verbatim sink expression check in post_src
        sink = finding.sink_expression.strip()
        if not sink or sink not in unit.post_src:
            return False, f"Sink expression '{sink}' does not appear verbatim in post_src"

        # 4. Evidence line numbers validation
        post_lines_count = len(unit.post_src.splitlines())
        if finding.evidence_lines:
            for line_no in finding.evidence_lines:
                # Accept either relative line numbers (1..post_lines_count) or
                # absolute ones (start_line..start_line + post_lines_count).
                rel_line = line_no
                if line_no >= unit.start_line:
                    rel_line = line_no - unit.start_line + 1
                # No slack. The `+ 5` here accepted lines that do not exist in the
                # unit, which is exactly the hallucination this gate is for.
                if rel_line < 1 or rel_line > post_lines_count:
                    return (
                        False,
                        f"Evidence line {line_no} falls outside post_src bounds "
                        f"(1..{post_lines_count})",
                    )

        return True, None


def map_finding_to_evidence(
    finding: LLMFinding,
    unit: ChangeUnit,
    agent_id: str,
    agent_version: str,
    raw_score: float = 1.0,
    confidence: float = 1.0,
) -> Evidence:
    """Convert a validated LLMFinding into a canonical Evidence payload."""
    f_key = unit.key_for(finding.cwe)

    explanation = (
        f"{finding.title} ({finding.cwe}): {finding.rationale} "
        f"Intent: {finding.functional_intent} Violates: {finding.violated_safety_invariant}"
    )

    artifacts = [
        Artifact(
            artifact_type="semantic_intent",
            content={
                "functional_intent": finding.functional_intent,
                "untrusted_data_sources": finding.untrusted_data_sources,
                "violated_safety_invariant": finding.violated_safety_invariant,
                "exploitability": finding.exploitability,
            },
        ),
        Artifact(
            artifact_type="sink_location",
            content={
                "file": unit.file,
                "symbol": unit.symbol,
                "sink_expression": finding.sink_expression,
                "evidence_lines": finding.evidence_lines,
                "start_line": finding.start_line,
                "end_line": finding.end_line,
            },
        ),
    ]

    return Evidence.detection(
        agent_id=agent_id,
        agent_version=agent_version,
        unit_id=unit.unit_id,
        finding_key=f_key,
        cwe=finding.cwe,
        raw_score=raw_score,
        confidence=confidence,
        explanation=explanation,
        artifacts=artifacts,
    )
