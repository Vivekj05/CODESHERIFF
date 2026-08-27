"""Unit tests for Multi-Agent Debate & Conflict Synthesizer."""

import pytest
from codesheriff_engine.config import EngineConfig
from codesheriff_engine.contracts import Evidence
from codesheriff_engine.fusion.bayes import FusionResult
from codesheriff_engine.fusion.debate import resolve_agent_conflict


def test_debate_skipped_when_no_conflict() -> None:
    ev1 = Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="u1",
        finding_key="k1",
        cwe="CWE-89",
        raw_score=0.85,
        explanation="SQLi taint",
    )
    ev2 = Evidence(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id="u1",
        finding_key="k1",
        cwe="CWE-89",
        raw_score=0.80,
        explanation="SQLi semantic",
    )

    fusion = FusionResult(
        finding_key="k1",
        posterior_probability=0.85,
        is_alert_worthy=True,
        evidence_list=[ev1, ev2],
        consensus_rationale="",
    )

    cfg = EngineConfig(conflict_threshold=0.50)
    resolved = resolve_agent_conflict(fusion, "def foo(): pass", cfg)

    # Conflict delta is 0.05 < 0.50 => no change
    assert resolved.posterior_probability == 0.85
    assert resolved.consensus_rationale == ""


def test_debate_resolves_sanitized_code_as_false_alarm() -> None:
    # Static says high danger (0.95), Semantic says safe/sanitized (0.10)
    ev1 = Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="u1",
        finding_key="k1",
        cwe="CWE-89",
        raw_score=0.95,
        explanation="Detected string in query",
    )
    ev2 = Evidence(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id="u1",
        finding_key="k1",
        cwe="CWE-89",
        raw_score=0.10,
        explanation="Value is properly parameterized and sanitized",
    )

    fusion = FusionResult(
        finding_key="k1",
        posterior_probability=0.75,
        is_alert_worthy=True,
        evidence_list=[ev1, ev2],
        consensus_rationale="",
    )

    code_snippet = (
        "def get_user(uid):\n"
        "    sanitized_id = int(uid)\n"
        "    return cursor.execute('SELECT * FROM users WHERE id = %s', (sanitized_id,))\n"
    )

    cfg = EngineConfig(conflict_threshold=0.50)
    resolved = resolve_agent_conflict(fusion, code_snippet, cfg)

    # Score delta is 0.85 >= 0.50 => debate runs
    assert resolved.posterior_probability <= 0.30
    assert resolved.is_alert_worthy is False
    assert "False Alarm" in resolved.consensus_rationale or "sanitiz" in resolved.consensus_rationale.lower()


def test_debate_resolves_danger_sink_as_vulnerable() -> None:
    # Static says high danger (0.95), Semantic low (0.20), but code has direct os.system
    ev1 = Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="u2",
        finding_key="k2",
        cwe="CWE-78",
        raw_score=0.95,
        explanation="Command injection sink",
    )
    ev2 = Evidence(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id="u2",
        finding_key="k2",
        cwe="CWE-78",
        raw_score=0.20,
        explanation="Developer intended utility run",
    )

    fusion = FusionResult(
        finding_key="k2",
        posterior_probability=0.60,
        is_alert_worthy=False,
        evidence_list=[ev1, ev2],
        consensus_rationale="",
    )

    code_snippet = "def run(cmd):\n    os.system(f'run {cmd}')\n"

    cfg = EngineConfig(conflict_threshold=0.50)
    resolved = resolve_agent_conflict(fusion, code_snippet, cfg)

    assert resolved.posterior_probability >= 0.70
    assert resolved.is_alert_worthy is True
    assert "Vulnerability" in resolved.consensus_rationale
