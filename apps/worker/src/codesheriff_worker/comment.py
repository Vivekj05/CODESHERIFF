"""The pull request comment.

Chapter 6 made this the end of a real pipeline. Chapter 9 gives it something to report: the
five hardcoded abstentions are gone, and what is rendered now is what four witnesses
actually said about each changed function, and the posterior that came out of it.

**Every number is labelled provisional, on every render (D-032, D-010).** The likelihood
ratios, the prior and the threshold are hand-set; Chapter 14 fits them on the calibration
split. A probability shown without its calibration state is precisely the unearned
confidence this project exists to argue against, so the state is not a footnote here — it
is the first line under the heading, and `apps/worker` has no way to render a posterior
without it.

**No agent prose reaches this comment.** Everything rendered below is drawn from closed
sets and numbers: CWE identifiers from `IN_SCOPE_CWES`, witness names from `WITNESSES`,
stances from an enum, likelihood ratios and probabilities as floats. Agent explanations are
free text — the semantic agent's is LLM output shaped by attacker-controlled source — and
`AUDIT.md` 0.4 records that there is no rationale screening yet. Rationales land here when
they arrive screened, in Chapter 11. Until then the structured breakdown carries the whole
story, and it is the part that explains the number anyway.

**Nothing from the pull request is echoed.** No title, no branch name, no description, no
file content, and no file *path* (D-050) — a path is chosen by whoever opened the pull
request, and a name like `` x`](javascript:…)`.py `` escapes a markdown table cell. That
also means a finding is not located here; locations belong on the dashboard, behind
rendering that escapes them (Chapter 16). Coverage is counts and plain words.
"""

from __future__ import annotations

import uuid
from collections import Counter

from codesheriff_contracts import CONTRACT_VERSION, Evidence, EvidenceKind
from codesheriff_engine.extraction import ExtractionResult, SkipReason
from codesheriff_engine.fusion import FusionResult, Stance

SKIP_WORDING: dict[SkipReason, str] = {
    SkipReason.FILE_REMOVED: "deleted",
    SkipReason.LANGUAGE_UNSUPPORTED: "not Python",
    SkipReason.CONTENT_UNAVAILABLE: "unreadable or over the size budget",
    SkipReason.NO_CHANGED_LINES: "unchanged in content",
}
"""Plain English for each skip reason.

A reader of the comment is told what was *not* looked at, in words. The enum value is the
machine name and belongs in the log and the database; a table cell reading
`language_unsupported` asks a developer to learn this system's vocabulary to find out that
their TypeScript was not scanned."""

STANCE_WORDING: dict[Stance, str] = {
    Stance.DETECTED: "🚨 detected",
    Stance.SILENT: "🔇 looked, found nothing",
    Stance.NEUTRAL: "⚪ no statement",
}
"""Three stances, three renderings, always.

A silence that rendered like an abstention would hide the distinction D-005 exists to
preserve — and it is the distinction that decides whether the witness pushed the number
down or left it alone, which is the one thing a reader of this table wants to know."""

PROVISIONAL_BANNER = (
    "> ⚠️ **Provisional, not calibrated.** The likelihood ratios, the prior and the alert "
    "threshold below are hand-set values, not measured ones. CodeSheriff's claim is that a "
    "stated 87% means right about 87% of the time — that claim is not yet supported by these "
    "numbers, and they should be read as a working estimate rather than a probability."
)


def marker_for(audit_id: uuid.UUID) -> str:
    """An HTML comment identifying which audit owns a comment.

    Invisible when rendered, and the only reliable way to recognise this bot's own comment
    later: the comment id is stored on the audit row, but a row can be lost and a comment
    cannot be matched by its text once the text starts varying.
    """
    return f"<!-- codesheriff:audit:{audit_id} -->"


def coverage_line(result: ExtractionResult) -> str:
    """What this audit extracted, and what it did not look at. Counts and reasons only.

    Reported even when nothing was skipped, because "we analysed 4 functions" and "we
    analysed nothing and said so quietly" have to be told apart by a reader in a hurry.
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


def witness_table(result: FusionResult) -> list[str]:
    """The odds product, written out one factor at a time.

    Four rows, always four — one per witness, including the ones that said nothing. That
    is the D-007 correction made visible: a reader can count the factors and see that an
    agent which abstained contributed exactly 1.0 rather than being left out of the
    arithmetic entirely.
    """
    lines = [
        "| Witness | Stance | Likelihood ratio | Why |",
        "| :--- | :--- | ---: | :--- |",
    ]
    for contribution in result.contributions:
        agents = ", ".join(f"`{a}`" for a in contribution.agent_ids) or "—"
        lines.append(
            f"| **{contribution.witness}** | {STANCE_WORDING[contribution.stance]} | "
            f"x{contribution.likelihood_ratio:.2f} | {contribution.note} {agents} |"
        )
    return lines


def _evidence_summary(evidence: list[Evidence]) -> str:
    """One line saying what the agents did across the whole audit."""
    counts = Counter(ev.kind for ev in evidence)
    parts = [
        f"{counts[EvidenceKind.DETECTION]} detection(s)",
        f"{counts[EvidenceKind.SILENCE]} silence(s)",
        f"{counts[EvidenceKind.ABSTENTION]} abstention(s)",
    ]
    return ", ".join(parts)


def render(
    audit_id: uuid.UUID,
    evidence: list[Evidence],
    findings: list[FusionResult],
    dashboard_url: str,
    extraction: ExtractionResult | None = None,
    prior_probability: float | None = None,
    alert_threshold: float | None = None,
) -> str:
    """The comment body: what was looked at, what each witness said, and what came out."""
    lines = ["## 🛡️ CodeSheriff", "", PROVISIONAL_BANNER, ""]

    if extraction is not None:
        lines += [coverage_line(extraction), ""]
    if evidence:
        lines += [f"Agents returned {_evidence_summary(evidence)}.", ""]

    if not findings:
        lines += [
            "**No finding.** No witness detected an in-scope weakness in the changed "
            "functions. That is a result rather than an absence of one: the agents that ran "
            "and found nothing said so, and the agents that could not run said that instead.",
            "",
        ]
    else:
        alerts = [f for f in findings if f.is_alert_worthy]
        threshold_note = (
            f" of which **{len(alerts)}** above the provisional alert threshold"
            f"{f' of {alert_threshold:.0%}' if alert_threshold is not None else ''}"
            if alerts
            else ", none above the provisional alert threshold"
        )
        lines += [
            f"**{len(findings)}** finding{'s' if len(findings) != 1 else ''}{threshold_note}.",
            "",
        ]

        for index, finding in enumerate(findings, start=1):
            flag = "🚨" if finding.is_alert_worthy else "🔍"
            lines += [
                f"### {flag} #{index} — `{finding.cwe}` · "
                f"P(vulnerable) ≈ **{finding.posterior_probability:.0%}** *(provisional)*",
                "",
            ]
            if prior_probability is not None:
                lines += [
                    f"Starting from a prior of {prior_probability:.0%}, four witnesses "
                    "contributed one likelihood ratio each:",
                    "",
                ]
            lines += witness_table(finding)
            lines.append("")

    lines += [
        "### What this number is, and is not",
        "",
        "The posterior above is a Bayesian fusion of every witness's statement — including "
        "the ones that found nothing, which push it down, and the ones that could not run, "
        "which leave it alone. The arithmetic is right. The *inputs* are not yet measured: "
        "no likelihood ratio here has been fitted against ground truth, and no threshold has "
        "been selected on a validation split. A calibrated number needs both.",
        "",
        f"[View this audit]({dashboard_url}) · contract `v{CONTRACT_VERSION}`",
        "",
        marker_for(audit_id),
    ]
    return "\n".join(lines)
