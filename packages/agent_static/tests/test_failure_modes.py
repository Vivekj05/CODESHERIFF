"""Failure mode tests: verify agent abstains on errors and never raises exceptions."""

from static_agent.agent import StaticAgent
from static_agent.contracts import ChangeUnit


def test_unsupported_language_abstains() -> None:
    unit = ChangeUnit(
        contract_version="1.0.0",
        unit_id="test-fail-01",
        repo="acme/app",
        language="cobol",
        file="app.cbl",
        symbol="main",
        pre_src="",
        post_src="DISPLAY 'HELLO WORLD'",
        changed_lines=[1],
        start_line=1,
        base_sha="aaa",
        head_sha="bbb",
    )
    agent = StaticAgent()
    results = agent.analyze(unit)

    assert len(results) > 0
    assert any(e.abstained for e in results)
    assert any(e.abstain_reason == "unsupported_language" for e in results if e.abstained)


def test_empty_post_src_does_not_raise() -> None:
    unit = ChangeUnit(
        contract_version="1.0.0",
        unit_id="test-fail-02",
        repo="acme/app",
        language="python",
        file="empty.py",
        symbol="empty",
        pre_src="",
        post_src="",
        changed_lines=[],
        start_line=1,
        base_sha="aaa",
        head_sha="bbb",
    )
    agent = StaticAgent()
    results = agent.analyze(unit)
    assert isinstance(results, list)
