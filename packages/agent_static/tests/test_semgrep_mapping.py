"""Tests for SARIF mapping functions."""

from codesheriff_contracts import ChangeUnit, EvidenceKind
from static_agent.semgrep.mapping import map_sarif_result_to_evidence


def _unit() -> ChangeUnit:
    return ChangeUnit(
        unit_id="unit-001",
        repo="acme/app",
        language="python",
        file="app/db.py",
        symbol="exec_sql",
        post_src="def exec_sql(q):\n    cursor.execute(query)\n",
        changed_lines=[1, 2],
        base_sha="aaa",
        head_sha="bbb",
    )


def _sarif(rule_id: str, text: str) -> dict:
    return {
        "ruleId": rule_id,
        "message": {"text": text},
        "locations": [
            {
                "physicalLocation": {
                    "region": {"startLine": 42, "snippet": {"text": "cursor.execute(query)"}}
                }
            }
        ],
    }


def test_semgrep_mapping_sqli() -> None:
    unit = _unit()
    ev = map_sarif_result_to_evidence(
        result=_sarif("python.lang.security.audit.sqli.sql-injection", "Possible SQL injection."),
        unit=unit,
    )
    assert ev is not None
    assert ev.kind is EvidenceKind.DETECTION
    assert ev.cwe == "CWE-89"
    assert ev.agent_id == "structural.semgrep"


def test_semgrep_and_taint_agree_on_the_key() -> None:
    """The two static backends must be able to collide on one bug.

    They previously could not: this mapper keyed on a SARIF text snippet while the
    taint engine keyed on AST node text, so two backends inside one agent produced
    two keys for the same finding (AUDIT.md 1.1).
    """
    unit = _unit()
    ev = map_sarif_result_to_evidence(result=_sarif("sqli.rule", "SQL injection"), unit=unit)
    assert ev is not None
    assert ev.finding_key == unit.key_for("CWE-89")


def test_out_of_scope_rule_is_dropped_not_relabelled() -> None:
    """IN_SCOPE_CWES is closed. An unmappable rule yields None, not a CWE-200 invention."""
    unit = _unit()
    ev = map_sarif_result_to_evidence(
        result=_sarif("python.lang.best-practice.unused-variable", "Unused variable."),
        unit=unit,
    )
    assert ev is None
