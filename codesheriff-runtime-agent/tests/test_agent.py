"""Tests for RuntimeAgent end-to-end analysis."""

from runtime_agent.agent import RuntimeAgent
from runtime_agent.contracts import ChangeUnit


def test_clean_execution(sample_change_unit: ChangeUnit) -> None:
    agent = RuntimeAgent()
    evidence_list = agent.analyze(sample_change_unit)

    assert len(evidence_list) == 1
    assert evidence_list[0].raw_score == 0.0
    assert not evidence_list[0].abstained
    assert "passed without crashes" in evidence_list[0].explanation


def test_unsupported_language_abstention(sample_change_unit: ChangeUnit) -> None:
    sample_change_unit.language = "ruby"
    agent = RuntimeAgent()
    evidence_list = agent.analyze(sample_change_unit)

    assert len(evidence_list) == 1
    assert evidence_list[0].abstained
    assert evidence_list[0].abstain_reason == "unsupported_language"


def test_sensitive_file_access_detection(sample_change_unit: ChangeUnit) -> None:
    sample_change_unit.post_src = "import sys\nsys.stderr.write('Reading /etc/passwd\\n')\n"
    agent = RuntimeAgent()
    evidence_list = agent.analyze(sample_change_unit)

    assert len(evidence_list) == 1
    assert not evidence_list[0].abstained
    assert evidence_list[0].cwe == "CWE-200"
    assert evidence_list[0].raw_score > 0.8
