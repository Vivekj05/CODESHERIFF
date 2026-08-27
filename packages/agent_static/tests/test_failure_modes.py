"""Failure mode tests: verify agent abstains on errors and never raises exceptions."""

from codesheriff_contracts import ChangeUnit, EvidenceKind
from static_agent.agent import StaticAgent


def test_unsupported_language_abstains() -> None:
    unit = ChangeUnit(
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
    abstentions = [e for e in results if e.kind is EvidenceKind.ABSTENTION]
    assert any(e.reason == "unsupported_language" for e in abstentions)
    # Never SILENCE: the agent could not read this language at all, so it has no
    # opinion to offer. Silence here would be counted as reassurance (D-005).
    assert not any(e.kind is EvidenceKind.SILENCE for e in results)


def test_empty_post_src_does_not_raise() -> None:
    unit = ChangeUnit(
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
