"""Tests for Cross-PR Security Control Bypass Detection."""

from typing import Any, Dict
from context_agent.contracts import ChangeUnit
from context_agent.rag.ingest import create_hybrid_pr_document
from context_agent.reasoning.analyzer import evaluate_cross_pr_regression


def test_cross_pr_bypass_detection(
    sample_bypassing_unit: ChangeUnit, sample_past_pr: Dict[str, Any]
) -> None:
    doc = create_hybrid_pr_document(sample_past_pr)
    ev_list = evaluate_cross_pr_regression(sample_bypassing_unit, [doc])
    assert len(ev_list) == 1
    ev = ev_list[0]
    assert ev.cwe == "CWE-862"
    assert "Cross-PR Security Control Bypass" in ev.explanation
