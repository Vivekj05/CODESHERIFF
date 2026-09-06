"""Tests for JavaScript taint engine analysis."""

from codesheriff_contracts import ChangeUnit, EvidenceKind
from static_agent.config import StaticConfig
from static_agent.taint.engine import analyze_taint


def test_js_eval_injection() -> None:
    unit = ChangeUnit(
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
    detections = [e for e in results if e.kind is EvidenceKind.DETECTION]
    assert len(detections) == 1
    assert detections[0].cwe == "CWE-94"
