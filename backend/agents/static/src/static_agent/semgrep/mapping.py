"""SARIF mapping for Semgrep rule results to Evidence objects."""

import re
from collections.abc import Iterable, Mapping
from typing import Any

from codesheriff_contracts import IN_SCOPE_CWES, Artifact, ChangeUnit, Evidence
from static_agent.scoring import calculate_raw_score

NARROWER_CWES: dict[str, str] = {
    "CWE-95": "CWE-94",  # Eval Injection, ChildOf Code Injection
    "CWE-96": "CWE-94",  # Static Code Injection, ChildOf Code Injection
}
"""MITRE children that the pinned rules tag, mapped to the in-scope parent they specialise.

Only pairs where the child really is a ChildOf the parent, and only ones the pinned rules use: the
`exec()` rules say CWE-95, and reporting them as anything but CWE-94 would key them apart from the
taint and semantic witnesses' finding on the same line. Nothing is mapped *up* to a broader CWE —
CWE-77 is the parent of CWE-78, not a kind of it — and no tag is mapped sideways.
"""

_CWE_TAG = re.compile(r"^(CWE-\d+)\b")


def cwes_from_tags(tags: Iterable[str]) -> list[str]:
    """The CWE identifiers in a SARIF rule's `properties.tags`, in their stated order."""
    return [m.group(1) for tag in tags if (m := _CWE_TAG.match(str(tag)))]


def in_scope_cwe(cwes: Iterable[str]) -> str | None:
    """The first tagged CWE that is in scope, directly or as a listed child; else None."""
    for cwe in cwes:
        mapped = NARROWER_CWES.get(cwe, cwe)
        if mapped in IN_SCOPE_CWES:
            return mapped
    return None


def rule_cwes(sarif_run: Mapping[str, Any]) -> dict[str, list[str]]:
    """Rule id to its tagged CWEs, from the run's own rule descriptors."""
    rules = sarif_run.get("tool", {}).get("driver", {}).get("rules", [])
    return {
        str(rule.get("id")): cwes_from_tags(rule.get("properties", {}).get("tags", []))
        for rule in rules
        if rule.get("id")
    }


AGENT_ID = "structural.semgrep"

AGENT_VERSION = "0.2.0"
"""0.2.0: pinned rules and build (D-104). 0.1.0 fetched `p/...` from the registry per run, so no
two runs were known to use the same backend, and it was never observed live on the corpus."""

COVERED_CWES: frozenset[str] = frozenset(
    {"CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-502", "CWE-798", "CWE-918"}
)
"""The in-scope CWEs the pinned Python rules are tagged with, directly or through
`NARROWER_CWES`. Bounds this backend's SILENCE (D-006): it has no rule for CWE-862 or CWE-639, so
its silence must not count against them. `test_covered_cwes_match_the_pinned_rules` recomputes
this from the rule files whenever they are present."""


def map_sarif_result_to_evidence(
    result: dict[str, Any],
    unit: ChangeUnit,
    cwes_by_rule: Mapping[str, list[str]],
    agent_version: str = AGENT_VERSION,
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

    # The rule's own CWE tags decide, never its id or message (D-104). Keyword guessing mapped
    # `exec-detected` — Python's exec(), CWE-95 — to command injection because the id contains
    # "exec", which keyed it apart from every other witness's CWE-94 finding on the same line.
    cwe = in_scope_cwe(cwes_by_rule.get(rule_id, []))
    if cwe is None:
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
