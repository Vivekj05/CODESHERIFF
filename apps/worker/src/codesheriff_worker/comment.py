"""The pull request comment.

Chapter 6 is the plumbing seam: a verified webhook becomes a queued audit becomes a comment on a
real pull request, with no analysis in between. The evidence below is hardcoded, and every piece of
it is an ABSTENTION — which is the truth, not a placeholder. An agent that could not run abstains
with a reason (`CLAUDE.md`, "Agents never raise"), and four agents that do not exist yet could not
run. Returning nothing, or rendering an empty "no vulnerabilities found", is the exact failure
`AUDIT.md` 4.4 documents: a system that says "clean" when it has not looked.

**No probability appears here.** D-032 requires a probability to arrive with its calibration state,
and there is nothing calibrated to state: no corpus exists, the prior and the threshold are
asserted values, and no agent has produced a single piece of real evidence. A number rendered now
would be exactly the unearned confidence this project exists to argue against.

**Nothing from the pull request is echoed.** No title, no branch name, no description, no file
content. Those are attacker-controlled, and `AUDIT.md` 0.4 is what happens when untrusted text
reaches a markdown table unescaped. When a rationale does need rendering — Chapter 11 — it arrives
screened, and this module stays the only place that builds the body.
"""

from __future__ import annotations

import uuid

from codesheriff_contracts import CONTRACT_VERSION, Evidence, EvidenceKind

PENDING_AGENTS: tuple[tuple[str, str, str], ...] = (
    ("structural.taint", "0.0.0", "Chapter 10 — the taint engine"),
    ("structural.semgrep", "0.0.0", "Chapter 9 — the Semgrep backend"),
    ("semantic.hosted", "0.0.0", "Chapter 11 — the semantic agent"),
    ("context.rag", "0.0.0", "Chapter 12 — the context agent"),
    ("runtime.sfi", "0.0.0", "Chapter 13 — the runtime agent"),
)
"""The five backends, four agents and the chapter each one lands in.

`structural.taint` and `structural.semgrep` are two backends of one agent and emit evidence
separately, which is why there are five rows and four sources of independent failure.
"""

ABSTENTION_REASON = "pipeline_not_implemented"


def marker_for(audit_id: uuid.UUID) -> str:
    """An HTML comment identifying which audit owns a comment.

    Invisible when rendered, and the only reliable way to recognise this bot's own comment later:
    the comment id is stored on the audit row, but a row can be lost and a comment cannot be
    matched by its text once the text starts varying.
    """
    return f"<!-- codesheriff:audit:{audit_id} -->"


def pending_evidence(audit_id: uuid.UUID) -> list[Evidence]:
    """One abstention per backend, built through the sanctioned constructor.

    `unit_id` names the audit rather than a change unit because there are no change units yet —
    extraction is Chapter 8. This evidence is deliberately never persisted for the same reason:
    `evidence` rows hang off a `change_units` row, and inventing one to hold an abstention would
    put a function nobody analysed into the table that records what was analysed.
    """
    return [
        Evidence.abstention(
            agent_id=agent_id,
            agent_version=version,
            unit_id=f"audit:{audit_id}",
            reason=ABSTENTION_REASON,
            explanation=f"Not built yet — {chapter}.",
        )
        for agent_id, version, chapter in PENDING_AGENTS
    ]


def render(audit_id: uuid.UUID, evidence: list[Evidence], dashboard_url: str) -> str:
    """The comment body: what ran, what did not, and why there is no number."""
    lines = [
        "## 🛡️ CodeSheriff",
        "",
        "**No analysis has run on this pull request yet.**",
        "",
        "The pipeline is connected end to end — this webhook delivery was signature-verified, an "
        "audit was queued, and a worker posted this comment — but the four analysis agents are "
        "not built. Every one of them abstained, which is the honest answer: an agent that could "
        "not run reports that it could not run, and never reports that it found nothing.",
        "",
        "| Backend | Evidence | Reason |",
        "| :--- | :--- | :--- |",
    ]

    for item in evidence:
        lines.append(
            f"| `{item.agent_id}` | {_stance(item)} | {item.explanation} |",
        )

    lines += [
        "",
        "### Why there is no probability here",
        "",
        "CodeSheriff's claim is a **calibrated** posterior — a stated 87% has to mean right about "
        "87% of the time, measured against ground truth. No corpus exists yet, so no likelihood "
        "ratio has been fitted and no threshold has been selected. Showing a number now would be "
        "the unearned confidence this project exists to argue against.",
        "",
        f"[View this audit]({dashboard_url}) · contract `v{CONTRACT_VERSION}`",
        "",
        marker_for(audit_id),
    ]
    return "\n".join(lines)


def _stance(item: Evidence) -> str:
    """How one piece of evidence reads in the table.

    Three kinds, three renderings, always — a silence that rendered like an abstention would hide
    the distinction D-005 exists to preserve.
    """
    if item.kind is EvidenceKind.ABSTENTION:
        return "⚪ Abstained"
    if item.kind is EvidenceKind.SILENCE:
        covered = ", ".join(sorted(item.covered_cwes))
        return f"🔇 Silent (covers {covered})"
    return "🚨 Detection"
