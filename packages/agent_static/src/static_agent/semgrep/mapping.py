"""SARIF mapping for Semgrep rule results to Evidence objects."""

from typing import Any, Dict, Optional
from static_agent.contracts import Artifact, Evidence, finding_key
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
}


def map_sarif_result_to_evidence(
    result: Dict[str, Any],
    unit_id: str,
    file_path: str,
    symbol: Optional[str],
    is_test_file: bool,
    agent_version: str = "0.1.0",
) -> Evidence:
    """Map a SARIF result dictionary to an Evidence contract object."""
    rule_id = result.get("ruleId", "unknown-rule")
    message = result.get("message", {}).get("text", f"Semgrep rule {rule_id} matched.")
    
    cwe = "CWE-89" if "sql" in rule_id.lower() else "CWE-78" if "exec" in rule_id.lower() else None
    if not cwe:
        for kw, mapped_cwe in CWE_MAPPING.items():
            if kw in rule_id.lower() or kw in message.lower():
                cwe = mapped_cwe
                break
    if not cwe:
        cwe = "CWE-200"  # Default generic information exposure / weakness

    locations = result.get("locations", [])
    line = 1
    snippet = rule_id
    if locations:
        phys = locations[0].get("physicalLocation", {})
        line = phys.get("region", {}).get("startLine", 1)
        snippet = phys.get("region", {}).get("snippet", {}).get("text", rule_id)

    f_key = finding_key(file_path, symbol, cwe, snippet)
    score = calculate_raw_score(
        danger="high",
        partial_sanitizer=False,
        path_length=2,
        network_facing=True,
        is_test_file=is_test_file,
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

    return Evidence(
        agent_id="structural.semgrep",
        agent_version=agent_version,
        unit_id=unit_id,
        finding_key=f_key,
        cwe=cwe,
        raw_score=score,
        confidence=0.85,
        explanation=f"Semgrep rule {rule_id} matched at line {line}: {message}",
        artifacts=[artifact],
        abstained=False,
        abstain_reason=None,
    )
