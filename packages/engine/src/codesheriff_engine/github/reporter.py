"""GitHub Markdown review comment rendering.

Rendering only. `post_pr_review_comment` lived here until Chapter 6 and is gone: it authenticated
with a personal access token over blocking `requests`, and skipped silently when the token was
absent — so a misconfigured deployment analysed pull requests and told nobody. Writing to GitHub is
now `apps/worker`'s `GitHubGateway`, which authenticates as the installation and raises.

This function still renders the pre-Chapter-9 fusion shape; the findings page rewrites it in
Chapter 16.
"""

from __future__ import annotations

import logging

from codesheriff_contracts import EvidenceKind
from codesheriff_engine.fusion.bayes import FusionResult

logger = logging.getLogger(__name__)


def format_github_comment(
    fusion_results: list[FusionResult],
    pr_title: str = "",
) -> str:
    """Format fusion results into a structured Markdown review comment for a PR."""
    comment = "## 🛡️ CodeSheriff Security Review\n\n"
    if pr_title:
        comment += f"> PR: **{pr_title}**\n\n"

    alert_findings = [f for f in fusion_results if f.is_alert_worthy]

    if not alert_findings:
        comment += (
            "✅ **No security vulnerabilities detected.**\n"
            "All multi-agent Bayesian safety checks passed across all analyzed code changes.\n"
        )
        return comment

    comment += (
        f"⚠️ **Security Alert**: Detected **{len(alert_findings)}** potential "
        "vulnerability issue(s) requiring attention.\n\n"
    )

    for idx, f in enumerate(alert_findings, start=1):
        prob_pct = f"{f.posterior_probability * 100:.1f}%"
        cwe_str = f.cwe or "CWE-Unknown"
        title_str = f.title or "Potential Security Flaw"
        file_str = f"`{f.file}`" if f.file else "N/A"
        severity_badge = f.severity.upper() if f.severity else "HIGH"

        comment += f"### 🚨 #{idx}: {title_str} (Probability: `{prob_pct}`)\n"
        comment += f"- **File:** {file_str}\n"
        comment += f"- **CWE:** `{cwe_str}`\n"
        comment += f"- **Severity:** `{severity_badge}`\n\n"

        comment += "| Agent | Stance | Score | Rationale / Evidence |\n"
        comment += "| :--- | :--- | :--- | :--- |\n"

        for item in f.evidence_list:
            if item.kind is EvidenceKind.ABSTENTION:
                stance = "⚪ Abstain"
                score_str = "—"
                rationale_str = f"Could not analyse: {item.reason or item.explanation}"
            elif item.kind is EvidenceKind.SILENCE:
                # Shown, not hidden. That an agent looked and found nothing is part of
                # why the posterior is what it is; omitting it makes the number
                # unexplainable (PLAN.md Chapter 16).
                covered = ", ".join(sorted(item.covered_cwes))
                stance = "🔇 Silent"
                score_str = "—"
                rationale_str = f"Analysed, no finding. Covers: {covered}"
            elif item.raw_score >= 0.5:
                stance = "⚠️ Alert"
                score_str = f"`{item.raw_score:.2f}`"
                rationale_str = item.explanation
            else:
                stance = "🟢 Safe"
                score_str = f"`{item.raw_score:.2f}`"
                rationale_str = item.explanation

            comment += f"| `{item.agent_id}` | {stance} | {score_str} | {rationale_str} |\n"

        if f.consensus_rationale:
            comment += f"\n**Multi-Agent Debate Resolution:**\n> {f.consensus_rationale}\n"

        comment += "\n---\n"

    comment += (
        "\n*Automated review by [CodeSheriff](https://github.com/) "
        "Bayesian Multi-Agent Security Engine.*"
    )
    return comment
