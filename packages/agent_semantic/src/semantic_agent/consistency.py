"""Self-consistency sampling and finding clustering engine."""

from __future__ import annotations

from typing import Literal

from codesheriff_contracts import ChangeUnit, Evidence
from semantic_agent.mapping import map_finding_to_evidence
from semantic_agent.schema import LLMFinding, LLMResponse

SeverityType = Literal["critical", "high", "medium", "low"]
ExploitabilityType = Literal["direct", "conditional", "theoretical"]

SEVERITY_WEIGHTS: dict[str, int] = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_NAMES: dict[int, SeverityType] = {4: "critical", 3: "high", 2: "medium", 1: "low"}

EXPLOITABILITY_WEIGHTS: dict[str, int] = {"direct": 3, "conditional": 2, "theoretical": 1}
EXPLOITABILITY_NAMES: dict[int, ExploitabilityType] = {
    3: "direct",
    2: "conditional",
    1: "theoretical",
}


def aggregate_self_consistency(
    sample_responses: list[LLMResponse],
    unit: ChangeUnit,
    agent_id: str,
    agent_version: str,
) -> list[Evidence]:
    """Cluster findings across n sample responses, calculating raw_score and merging details."""
    if not sample_responses:
        return []

    total_samples = len(sample_responses)
    clusters: dict[str, list[LLMFinding]] = {}

    for resp in sample_responses:
        for finding in resp.findings:
            # Keyed by CWE within the unit, not by the model's chosen wording for the
            # sink. Two samples describing one bug as `cursor.execute(q)` and
            # `cursor.execute` are the same finding and must cluster (D-004).
            key = unit.key_for(finding.cwe)
            if key not in clusters:
                clusters[key] = []
            clusters[key].append(finding)

    results: list[Evidence] = []
    for _key, findings_group in clusters.items():
        count = len(findings_group)
        raw_score = round(count / total_samples, 3)

        # Merge rationale: pick longest and enforce max length
        best_rationale = max((f.rationale for f in findings_group), key=len)[:400]

        # Merge severity: pick highest severity across samples
        highest_sev_val = max(SEVERITY_WEIGHTS.get(f.severity, 2) for f in findings_group)
        merged_severity: SeverityType = SEVERITY_NAMES.get(highest_sev_val, "medium")

        # Merge exploitability: pick most direct across samples
        highest_exp_val = max(
            EXPLOITABILITY_WEIGHTS.get(f.exploitability, 3) for f in findings_group
        )
        merged_exploitability: ExploitabilityType = EXPLOITABILITY_NAMES.get(
            highest_exp_val, "direct"
        )

        # Union of evidence lines
        union_lines = sorted(list(set(line for f in findings_group for line in f.evidence_lines)))

        # Union of untrusted data sources
        union_sources = sorted(
            list(set(src for f in findings_group for src in f.untrusted_data_sources))
        )

        # Calculate bounding line numbers
        start_line = min(f.start_line for f in findings_group)
        end_line = max(f.end_line for f in findings_group)

        # Representative finding for descriptions
        rep = findings_group[0]
        merged_finding = LLMFinding(
            functional_intent=rep.functional_intent[:200],
            untrusted_data_sources=union_sources,
            violated_safety_invariant=rep.violated_safety_invariant[:300],
            cwe=rep.cwe.strip().upper(),
            title=rep.title[:80],
            file=unit.file,
            start_line=start_line,
            end_line=end_line,
            sink_expression=rep.sink_expression.strip(),
            severity=merged_severity,
            rationale=best_rationale,
            evidence_lines=union_lines,
            exploitability=merged_exploitability,
        )

        ev = map_finding_to_evidence(
            finding=merged_finding,
            unit=unit,
            agent_id=agent_id,
            agent_version=agent_version,
            raw_score=raw_score,
            confidence=raw_score,
        )
        results.append(ev)

    return results
