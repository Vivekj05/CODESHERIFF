"""Tests for scoring module formula and terms."""

from static_agent.scoring import calculate_raw_score, clamp


def test_clamp() -> None:
    assert clamp(-0.5) == 0.0
    assert clamp(1.5) == 1.0
    assert clamp(0.7) == 0.7


def test_scoring_weights() -> None:
    critical_score = calculate_raw_score(danger="critical", is_test_file=False)
    high_score = calculate_raw_score(danger="high", is_test_file=False)
    test_score = calculate_raw_score(danger="high", is_test_file=True)

    assert critical_score > high_score
    assert high_score > test_score
