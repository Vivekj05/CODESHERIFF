"""Hallucination Gate and LLMFinding to Evidence mapper."""

from __future__ import annotations

import logging
from typing import Optional, Tuple
from semantic_agent.contracts import Artifact, ChangeUnit, Evidence, finding_key
from semantic_agent.schema import LLMFinding

logger = logging.getLogger(__name__)


class HallucinationGate:
    """Hard rejection gate preventing hallucinated findings from entering Evidence contracts."""

    @staticmethod
    def validate(finding: LLMFinding, unit: ChangeUnit) -> Tuple[bool, Optional[str]]:
        """Validate an LLMFinding against the ChangeUnit.

        Returns (is_valid, rejection_reason).
        """
        # 1. File path validation
        if finding.file.strip() != unit.file.strip():
            # Check if basename matches if paths differ slightly
            unit_file_base = unit.file.split("/")[-1].split("\\")[-1]
            finding_file_base = finding.file.split("/")[-1].split("\\")[-1]
            if unit_file_base != finding_file_base:
                return False, f"File path mismatch: finding.file='{finding.file}' vs unit.file='{unit.file}'"

        # 2. Verbatim sink expression check in post_src
        sink = finding.sink_expression.strip()
        if not sink or sink not in unit.post_src:
            return False, f"Sink expression '{sink}' does not appear verbatim in post_src"

        # 3. Evidence line numbers validation
        post_lines_count = len(unit.post_src.splitlines())
        if finding.evidence_lines:
            for line_no in finding.evidence_lines:
                # Accept relative line numbers (1..post_lines_count) or absolute line numbers (start_line..start_line+post_lines_count)
                rel_line = line_no
                if line_no >= unit.start_line:
                    rel_line = line_no - unit.start_line + 1
                if rel_line < 1 or rel_line > post_lines_count + 5:
                    return False, f"Evidence line {line_no} falls outside post_src bounds (1..{post_lines_count})"

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
    f_key = finding_key(unit.file, unit.symbol, finding.cwe, finding.sink_expression)
    
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

    return Evidence(
        agent_id=agent_id,
        agent_version=agent_version,
        unit_id=unit.unit_id,
        finding_key=f_key,
        cwe=finding.cwe.upper(),
        raw_score=raw_score,
        confidence=confidence,
        explanation=explanation,
        artifacts=artifacts,
        abstained=False,
        abstain_reason=None,
    )
