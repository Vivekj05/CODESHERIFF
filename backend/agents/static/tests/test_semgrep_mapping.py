"""Tests for SARIF mapping functions."""

import re
from pathlib import Path

import pytest
import yaml

from codesheriff_contracts import ChangeUnit, EvidenceKind
from static_agent.config import StaticConfig
from static_agent.semgrep.mapping import (
    COVERED_CWES,
    NARROWER_CWES,
    in_scope_cwe,
    map_sarif_result_to_evidence,
    rule_cwes,
)
from static_agent.semgrep.runner import verified_rule_paths

SQLI = "CWE-89: Improper Neutralization of Special Elements used in an SQL Command"
EVAL = "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code"


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
        cwes_by_rule={"python.lang.security.audit.sqli.sql-injection": ["CWE-89"]},
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
    ev = map_sarif_result_to_evidence(
        result=_sarif("sqli.rule", "SQL injection"),
        unit=unit,
        cwes_by_rule={"sqli.rule": ["CWE-89"]},
    )
    assert ev is not None
    assert ev.finding_key == unit.key_for("CWE-89")


def test_exec_is_code_injection_not_command_injection() -> None:
    """The keyword mapper read "exec" in the rule id as CWE-78. The rule says CWE-95 (D-104)."""
    unit = _unit()
    rule = "semgrep.rules.python.lang.security.audit.exec-detected.exec-detected"
    ev = map_sarif_result_to_evidence(
        result=_sarif(rule, "Detected the use of exec()."),
        unit=unit,
        cwes_by_rule={rule: ["CWE-95"]},
    )
    assert ev is not None
    assert ev.cwe == "CWE-94"
    assert ev.finding_key == unit.key_for("CWE-94")


def test_the_rule_id_and_message_are_never_read_for_a_cwe() -> None:
    """A rule tagged with nothing in scope is dropped however its id or message reads."""
    unit = _unit()
    rule = "python.sql.command.exec.injection"
    ev = map_sarif_result_to_evidence(
        result=_sarif(rule, "SQL injection via exec of a shell command"),
        unit=unit,
        cwes_by_rule={rule: ["CWE-939"]},
    )
    assert ev is None


def test_out_of_scope_rule_is_dropped_not_relabelled() -> None:
    """IN_SCOPE_CWES is closed. An unmappable rule yields None, not a CWE-200 invention."""
    unit = _unit()
    ev = map_sarif_result_to_evidence(
        result=_sarif("python.lang.best-practice.unused-variable", "Unused variable."),
        unit=unit,
        cwes_by_rule={},
    )
    assert ev is None


def test_only_children_map_to_parents() -> None:
    assert in_scope_cwe(["CWE-95"]) == "CWE-94"
    assert in_scope_cwe(["CWE-77"]) is None  # the parent of CWE-78, not a kind of it
    assert in_scope_cwe(["CWE-327", "CWE-78"]) == "CWE-78"
    assert set(NARROWER_CWES.values()) <= COVERED_CWES


def test_rule_cwes_reads_the_run_s_own_descriptors() -> None:
    run = {
        "tool": {
            "driver": {
                "rules": [
                    {"id": "a", "properties": {"tags": [SQLI, "HIGH CONFIDENCE", "security"]}},
                    {"id": "b", "properties": {"tags": [EVAL]}},
                    {"id": "c"},
                ]
            }
        }
    }
    assert rule_cwes(run) == {"a": ["CWE-89"], "b": ["CWE-95"], "c": []}


def test_covered_cwes_match_the_pinned_rules() -> None:
    """Semgrep's silence may only claim the CWEs its pinned Python rules can reach (D-006).

    Recomputed from the rule files, which are gitignored and fetched by hand (D-104), so this
    skips on a checkout without them rather than passing against nothing.
    """
    config = StaticConfig()
    try:
        paths = verified_rule_paths(config.semgrep_rules_dir, config.semgrep_rulesets)
    except Exception:
        pytest.skip("pinned Semgrep rules are not in .semgrep/rules/")
    reachable: set[str] = set()
    for path in paths:
        for rule in yaml.safe_load(Path(path).read_text(encoding="utf-8"))["rules"]:
            if "python" not in [lang.lower() for lang in rule.get("languages", [])]:
                continue
            tags = rule.get("metadata", {}).get("cwe", [])
            tags = [tags] if isinstance(tags, str) else tags
            cwes = [m.group(0) for t in tags if (m := re.match(r"CWE-\d+", str(t)))]
            for cwe in cwes:
                if (mapped := in_scope_cwe([cwe])) is not None:
                    reachable.add(mapped)
    assert reachable == COVERED_CWES
