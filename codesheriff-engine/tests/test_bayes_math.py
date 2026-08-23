"""Unit tests for Bayesian Odds and Likelihood Ratio fusion calculations."""

import pytest
from typing import List
from codesheriff_engine.contracts import Evidence
from codesheriff_engine.fusion.bayes import (
    compute_bayesian_fusion,
    fuse_all_evidence,
    get_likelihood_ratio,
)


def test_likelihood_ratio_tiers() -> None:
    # Test structural.taint tiers
    assert get_likelihood_ratio("structural.taint", 0.95) == 8.5
    assert get_likelihood_ratio("structural.taint", 0.80) == 8.5
    assert get_likelihood_ratio("structural.taint", 0.79) == 3.2
    assert get_likelihood_ratio("structural.taint", 0.50) == 3.2
    assert get_likelihood_ratio("structural.taint", 0.49) == 0.8
    assert get_likelihood_ratio("structural.taint", 0.10) == 0.8

    # Test semantic.hosted tiers
    assert get_likelihood_ratio("semantic.hosted", 0.90) == 12.0
    assert get_likelihood_ratio("semantic.hosted", 0.60) == 4.5
    assert get_likelihood_ratio("semantic.hosted", 0.30) == 0.5


def test_bayesian_single_agent_update() -> None:
    ev = Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="unit-1",
        finding_key="key-123",
        cwe="CWE-89",
        raw_score=0.90,  # LR = 8.5
        explanation="SQL injection taint",
    )

    # Prior P = 0.05 => Prior Odds = 0.05 / 0.95 = 0.0526315
    # Post Odds = 0.0526315 * 8.5 = 0.447368
    # Posterior P = 0.447368 / 1.447368 = 0.3091
    result = compute_bayesian_fusion("key-123", [ev], prior_p=0.05, alert_threshold=0.70)
    assert round(result.posterior_probability, 4) == 0.3091
    assert not result.is_alert_worthy  # 0.3091 < 0.70


def test_bayesian_multi_agent_consensus_triggers_alert(sample_evidence_list: List[Evidence]) -> None:
    # 3 agents agree on SQLi (structural: 0.95, semantic: 0.90, context: 0.85)
    # Post Odds = (0.05/0.95) * 8.5 * 12.0 * 4.2 = 22.547368
    # Posterior P = 22.547368 / 23.547368 = 0.9575
    key = sample_evidence_list[0].finding_key
    result = compute_bayesian_fusion(key, sample_evidence_list, prior_p=0.05, alert_threshold=0.70)

    assert result.posterior_probability >= 0.95
    assert result.is_alert_worthy is True
    assert result.cwe == "CWE-89"
    assert result.severity == "critical"


def test_bayesian_abstention_handling() -> None:
    abstention = Evidence.abstention(
        agent_id="context.rag",
        agent_version="0.1.0",
        unit_id="unit-1",
        reason="no_anchor",
    )

    result = compute_bayesian_fusion("key-abs", [abstention], prior_p=0.05)
    assert result.posterior_probability == 0.05
    assert not result.is_alert_worthy


def test_fuse_all_evidence_groups_by_key() -> None:
    ev1 = Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="unit-1",
        finding_key="key-A",
        cwe="CWE-89",
        raw_score=0.9,
        explanation="SQLi",
    )
    ev2 = Evidence(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id="unit-1",
        finding_key="key-A",
        cwe="CWE-89",
        raw_score=0.9,
        explanation="SQLi semantic",
    )
    ev3 = Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="unit-1",
        finding_key="key-B",
        cwe="CWE-78",
        raw_score=0.3,
        explanation="Low danger",
    )

    results = fuse_all_evidence([ev1, ev2, ev3], prior_p=0.05)
    assert len(results) == 2
    # key-A should have higher probability and be first
    assert results[0].finding_key == "key-A"
    assert results[0].posterior_probability > results[1].posterior_probability
    assert results[1].finding_key == "key-B"
