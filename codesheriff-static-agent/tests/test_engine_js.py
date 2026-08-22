"""Tests for JavaScript taint engine analysis."""

from static_agent.config import StaticConfig
from static_agent.contracts import ChangeUnit
from static_agent.taint.engine import analyze_taint


def test_js_eval_injection() -> None:
    unit = ChangeUnit(
        contract_version="1.0.0",
        unit_id="test-js-01",
        repo="acme/app",
        language="javascript",
        file="server.js",
        symbol="handler",
        pre_src="function handler(req, res) {}",
        post_src="function handler(req, res) {\n    let code = req.query.code;\n    eval(code);\n}",
        changed_lines=[1, 2, 3],
        start_line=1,
        base_sha="aaa",
        head_sha="bbb",
    )
    results = analyze_taint(unit, StaticConfig())
    assert len(results) == 1
    assert results[0].cwe == "CWE-94"
