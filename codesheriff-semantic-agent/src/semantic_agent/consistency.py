"""Self-consistency sampling and finding clustering engine."""

from __future__ import annotations

from typing import Dict, List, Tuple
from semantic_agent.contracts import ChangeUnit, Evidence, finding_key
from semantic_agent.mapping import map_finding_to_evidence
from semantic_agent.schema import LLMFinding, LLMResponse

SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_NAMES = {4: "critical", 3: "high", 2: "medium", 1: "low"}


def aggregate_self_consistency(
    sample_responses: List[LLMResponse],
    unit: ChangeUnit,
    agent_id: str,
    agent_version: str,
) -> List[Evidence]:
    """Cluster findings across n sample responses, calculating raw_score and merging details."""
    if not sample_responses:
        return []

    total_samples = len(sample_responses)
    clusters: Dict[str, List[LLMFinding]] = {}

    for resp in sample_responses:
        for finding in resp.findings:
            key = finding_key(unit.file, unit.symbol, finding.cwe, finding.sink_expression)
            if key not in clusters:
                clusters[key] = []
            clusters[key].append(finding)

    results: List[Evidence] = []
    for key, findings_group in clusters.items():
        count = len(findings_group)
        raw_score = round(count / total_samples, 3)

        # Merge rationale: pick longest
        best_rationale = max((f.rationale for f in findings_group), key=len)

        # Merge severity: pick highest
        highest_sev_val = max(SEVERITY_WEIGHTS.get(f.severity, 1) for f in findings_group)
        merged_severity = SEVERITY_NAMES.get(highest_sev_val, "medium")

        # Union of evidence lines
        union_lines = sorted(list(set(line for f in findings_group for line in f.evidence_lines)))

        # Representative finding
        rep = findings_group[0]
        merged_finding = LLMFinding(
            functional_intent=rep.functional_intent,
            untrusted_data_sources=rep.untrusted_data_sources,
            violated_safety_invariant=rep.violated_safety_invariant,
            cwe=rep.cwe,
            title=rep.title,
            file=unit.file,
            start_line=rep.start_line,
            end_line=rep.end_line,
            sink_expression=rep.sink_expression,
            severity=merged_severity,
            rationale=best_rationale,
            evidence_lines=union_lines,
            exploitability=rep.exploitability,
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
