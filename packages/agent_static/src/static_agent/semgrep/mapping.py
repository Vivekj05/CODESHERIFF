"""SARIF mapping for Semgrep rule results to Evidence objects."""

from typing import Any

from codesheriff_contracts import IN_SCOPE_CWES, Artifact, ChangeUnit, Evidence
from static_agent.scoring import calculate_raw_score

CWE_MAPPING = {
    "sql": "CWE-89",
    "sqli": "CWE-89",
    "command": "CWE-78",
    "exec": "CWE-78",
    "xss": "CWE-79",
    "path": "CWE-22",
    "traversal": "CWE-22",
    "yaml": "CWE-502",
    "deserialization": "CWE-502",
    "eval": "CWE-94",
    "ssrf": "CWE-918",
    "request": "CWE-918",
    "hardcoded": "CWE-798",
    "secret": "CWE-798",
}

AGENT_ID = "structural.semgrep"

#: What this backend's rule-id keyword mapping can reach. Bounds its SILENCE (D-006).
COVERED_CWES: frozenset[str] = frozenset(CWE_MAPPING.values()) & IN_SCOPE_CWES


def map_sarif_result_to_evidence(
    result: dict[str, Any],
    unit: ChangeUnit,
    agent_version: str = "0.1.0",
) -> Evidence | None:
    """Map one SARIF result to Evidence, or None if it is out of scope.

    Takes the whole ChangeUnit rather than loose file/symbol strings so the key is
    built by `unit.key_for()` — the same call the taint engine makes. Two backends
    inside one agent previously could not collide on the same bug, because this one
    keyed on a SARIF text snippet while the taint engine keyed on AST node text
    (AUDIT.md 1.1).
    """
    rule_id = result.get("ruleId", "unknown-rule")
    message = result.get("message", {}).get("text", f"Semgrep rule {rule_id} matched.")

    cwe = "CWE-89" if "sql" in rule_id.lower() else "CWE-78" if "exec" in rule_id.lower() else None
    if not cwe:
        for kw, mapped_cwe in CWE_MAPPING.items():
            if kw in rule_id.lower() or kw in message.lower():
                cwe = mapped_cwe
                break
    if not cwe or cwe not in IN_SCOPE_CWES:
        # IN_SCOPE_CWES is closed (PROJECT_CONTEXT.md §6). A rule we cannot map to an
        # in-scope CWE is dropped, not relabelled: the previous CWE-200 default
        # invented a finding outside the set every calibrated number is fitted on.
        return None

    locations = result.get("locations", [])
    line = 1
    snippet = rule_id
    if locations:
        phys = locations[0].get("physicalLocation", {})
        line = phys.get("region", {}).get("startLine", 1)
        snippet = phys.get("region", {}).get("snippet", {}).get("text", rule_id)

    f_key = unit.key_for(cwe)
    score = calculate_raw_score(
        danger="high",
        partial_sanitizer=False,
        path_length=2,
        network_facing=True,
        is_test_file=unit.is_test_file,
    )

    artifact = Artifact(
        artifact_type="semgrep_match",
        content={
            "rule_id": rule_id,
            "message": message,
            "line": line,
            "snippet": snippet,
        },
    )

    return Evidence.detection(
        agent_id=AGENT_ID,
        agent_version=agent_version,
        unit_id=unit.unit_id,
        finding_key=f_key,
        cwe=cwe,
        raw_score=score,
        confidence=0.85,
        explanation=f"Semgrep rule {rule_id} matched at line {line}: {message}",
        artifacts=[artifact],
    )
