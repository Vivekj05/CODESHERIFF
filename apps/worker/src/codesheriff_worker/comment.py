"""The pull request comment.

Chapter 6 is the plumbing seam: a verified webhook becomes a queued audit becomes a comment on a
real pull request, with no analysis in between. The evidence below is hardcoded, and every piece of
it is an ABSTENTION — which is the truth, not a placeholder. An agent that could not run abstains
with a reason (`CLAUDE.md`, "Agents never raise"), and four agents that do not exist yet could not
run. Returning nothing, or rendering an empty "no vulnerabilities found", is the exact failure
`AUDIT.md` 4.4 documents: a system that says "clean" when it has not looked.

**No probability appears here.** D-032 requires a probability to arrive with its calibration state,
and there is nothing calibrated to state: the prior and the threshold are still asserted values
fitted against nothing, and no agent has produced a single piece of real evidence. A number
rendered now would be exactly the unearned confidence this project exists to argue against.

**Nothing from the pull request is echoed.** No title, no branch name, no description, no file
content — and, since Chapter 8, no file *path* either. Those are attacker-controlled, and
`AUDIT.md` 0.4 is what happens when untrusted text reaches a markdown table unescaped. Chapter 8
adds the one thing that can be said safely: how many functions were extracted and how many files
were skipped, as counts. When a rationale does need rendering — Chapter 11 — it arrives screened,
and this module stays the only place that builds the body.
"""

from __future__ import annotations

import uuid
from collections import Counter

from codesheriff_contracts import CONTRACT_VERSION, Evidence, EvidenceKind
from codesheriff_engine.extraction import ExtractionResult, SkipReason

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

SKIP_WORDING: dict[SkipReason, str] = {
    SkipReason.FILE_REMOVED: "deleted",
    SkipReason.LANGUAGE_UNSUPPORTED: "not Python",
    SkipReason.CONTENT_UNAVAILABLE: "unreadable or over the size budget",
    SkipReason.NO_CHANGED_LINES: "unchanged in content",
}
"""Plain English for each skip reason.

A reader of the comment is told what was *not* looked at, in words. The enum value is the machine
name and belongs in the log and the database; a table cell reading `language_unsupported` asks a
developer to learn this system's vocabulary to find out that their TypeScript was not scanned."""


def marker_for(audit_id: uuid.UUID) -> str:
    """An HTML comment identifying which audit owns a comment.

    Invisible when rendered, and the only reliable way to recognise this bot's own comment later:
    the comment id is stored on the audit row, but a row can be lost and a comment cannot be
    matched by its text once the text starts varying.
    """
    return f"<!-- codesheriff:audit:{audit_id} -->"


def pending_evidence(audit_id: uuid.UUID) -> list[Evidence]:
    """One abstention per backend, built through the sanctioned constructor.

    `unit_id` names the audit rather than a change unit, and still does now that Chapter 8 has
    made change units real: these five abstentions are statements about the *pipeline*, not about
    any one function. Writing one against every extracted unit would fill the table that will hold
    real evidence with `pipeline_not_implemented`, at five rows per changed function. Chapter 9
    replaces them with per-unit evidence that is worth persisting.
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


def coverage_line(result: ExtractionResult) -> str:
    """What this audit extracted, and what it did not look at.

    Counts and reasons only — **no file path is ever rendered here**. A path is chosen by whoever
    opened the pull request, so it is attacker-controlled text in exactly the way `AUDIT.md` 0.4
    describes, and a name like `` x`](javascript:…)`.py `` escapes a markdown table cell. The
    dashboard is where paths belong, behind rendering that escapes them (Chapter 16).

    Reported even when nothing was skipped, because "we analysed 4 functions" and "we analysed
    nothing and said so quietly" have to be told apart by a reader in a hurry.
    """
    units = len(result.units)
    summary = f"Extracted **{units}** changed {'function' if units == 1 else 'functions'}"

    if result.skipped:
        counts = Counter(skipped.reason for skipped in result.skipped)
        detail = ", ".join(
            f"{count} {SKIP_WORDING[reason]}" for reason, count in sorted(counts.items())
        )
        summary += f". Not analysed: {detail}"
    return summary + "."


def render(
    audit_id: uuid.UUID,
    evidence: list[Evidence],
    dashboard_url: str,
    extraction: ExtractionResult | None = None,
) -> str:
    """The comment body: what was looked at, what ran, what did not, and why there is no number."""
    lines = [
        "## 🛡️ CodeSheriff",
        "",
        "**No analysis has run on this pull request yet.**",
        "",
        "The pipeline is connected end to end — this webhook delivery was signature-verified, an "
        "audit was queued, the changed functions were extracted, and a worker posted this comment "
        "— but the four analysis agents are not built. Every one of them abstained, which is the "
        "honest answer: an agent that could not run reports that it could not run, and never "
        "reports that it found nothing.",
    ]

    if extraction is not None:
        lines += ["", coverage_line(extraction)]

    lines += [
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
        "87% of the time, measured against ground truth. The corpus that ground truth comes from "
        "now exists, but no likelihood ratio has been fitted against it and no threshold has been "
        "selected. Showing a number now would be the unearned confidence this project exists to "
        "argue against.",
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
