"""Unit tests for GitHub reporter formatting and API poster."""

import pytest
from codesheriff_engine.contracts import Evidence
from codesheriff_engine.fusion.bayes import FusionResult
from codesheriff_engine.github.reporter import format_github_comment, post_pr_review_comment


def test_format_clean_github_comment() -> None:
    comment = format_github_comment([], pr_title="Fix typos")
    assert "## 🛡️ CodeSheriff Security Review" in comment
    assert "No security vulnerabilities detected" in comment


def test_format_alert_github_comment() -> None:
    ev1 = Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id="u1",
        finding_key="k1",
        cwe="CWE-89",
        raw_score=0.92,
        explanation="SQL injection taint path found",
    )
    ev2 = Evidence(
        agent_id="semantic.hosted",
        agent_version="0.1.0",
        unit_id="u1",
        finding_key="k1",
        cwe="CWE-89",
        raw_score=0.88,
        explanation="Unsafe SQL concatenation",
    )

    fusion = FusionResult(
        finding_key="k1",
        posterior_probability=0.945,
        is_alert_worthy=True,
        evidence_list=[ev1, ev2],
        consensus_rationale="Both agents confirm direct taint into database query.",
        cwe="CWE-89",
        title="SQL Injection in user route",
        severity="critical",
        file="app/users.py",
    )

    comment = format_github_comment([fusion], pr_title="Add user query")

    assert "🚨 #1: SQL Injection in user route (Probability: `94.5%`)" in comment
    assert "`app/users.py`" in comment
    assert "`CWE-89`" in comment
    assert "`CRITICAL`" in comment
    assert "| `structural.taint` | ⚠️ Alert | `0.92` |" in comment
    assert "| `semantic.hosted` | ⚠️ Alert | `0.88` |" in comment
    assert "Both agents confirm direct taint into database query." in comment


def test_post_comment_skips_when_token_is_missing() -> None:
    res = post_pr_review_comment(
        repo_full_name="acme/repo",
        pr_number=42,
        comment_body="test",
        token=None,
    )
    assert res["status"] == "skipped"
    assert res["reason"] == "missing_github_token"
