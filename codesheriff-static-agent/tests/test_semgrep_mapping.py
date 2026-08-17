"""Tests for SARIF mapping functions."""

from static_agent.semgrep.mapping import map_sarif_result_to_evidence


def test_semgrep_mapping_sqli() -> None:
    sarif_result = {
        "ruleId": "python.lang.security.audit.sqli.sql-injection",
        "message": {"text": "Possible SQL injection detected."},
        "locations": [
            {
                "physicalLocation": {
                    "region": {"startLine": 42, "snippet": {"text": "cursor.execute(query)"}}
                }
            }
        ],
    }
    ev = map_sarif_result_to_evidence(
        result=sarif_result,
        unit_id="unit-001",
        file_path="app/db.py",
        symbol="exec_sql",
        is_test_file=False,
    )
    assert ev.cwe == "CWE-89"
    assert not ev.abstained
    assert ev.agent_id == "structural.semgrep"
