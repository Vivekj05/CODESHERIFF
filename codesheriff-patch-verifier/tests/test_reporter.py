"""Tests for GitHub PR comment reporter."""

from patch_verifier.contracts import ChangeUnit, Evidence
from patch_verifier.reporter.github_comment import format_pr_comment


def test_pr_comment_formatting(sample_change_unit: ChangeUnit, sample_evidence: Evidence) -> None:
    diff_snippet = "--- a/app.py\n+++ b/app.py\n+ # Fixed"
    comment = format_pr_comment(
        unit=sample_change_unit,
        posterior_prob=0.95,
        disagreement_index=0.002,
        verdict="VULNERABLE",
        evidence_list=[sample_evidence],
        patch_diff=diff_snippet,
        verified=True,
    )

    assert "🔴 VULNERABLE" in comment
    assert "95.0%" in comment
    assert "CWE-89" in comment
    assert "Verified Automated Security Patch" in comment
    assert diff_snippet in comment
