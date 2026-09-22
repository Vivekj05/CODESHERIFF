"""Draft, verify, retry — and stop, in every direction, with a reason.

Nine outcomes, because a patcher has more ways to produce nothing than to produce something and
collapsing them would make the pull request comment say "no suggestion" to a reader who cannot act
on it. "The model was never asked because the function is 40 KB" and "three repairs were drafted
and none survived the checks" are different facts about this system, and the second one is a defect
report waiting to be written into `DEFECTS.md`.

**Retries carry constraints, never drafts** (D-093). A rejected draft is model output shaped by
attacker-controlled source; returning it to the model as instruction would put untrusted text
outside the sentinel, which is the boundary the prompt is built around. Each attempt is drafted
fresh from the same unit with an accumulating list of rejection reasons in this system's own words.

**Three drafts, then nothing.** Not because three is special, but because a loop that keeps going
until something passes is selecting for a draft that satisfies the checks rather than one that
repairs the code — and the checks are cheap enough that the difference would not show from outside.

**A repair that verifies but cannot be anchored is not published, and the loop does not try
again for a narrower one.** Where a repair lands is a property of the pull request's diff, not of
the draft's quality, and re-drafting against it would be searching for a patch that fits the hunk
rather than the bug.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum

from codesheriff_contracts import ChangeUnit
from codesheriff_patch.config import PatchConfig
from codesheriff_patch.drafting import (
    DraftRequest,
    DraftUnavailableError,
    PatchModel,
    draft,
)
from codesheriff_patch.source import LineReplacement, line_replacement, parse
from codesheriff_patch.suggestion import Anchor, anchor_for
from codesheriff_patch.verify import (
    Rechecker,
    Verification,
    VerificationRequest,
    verify,
)

logger = logging.getLogger(__name__)


class ProposalOutcome(StrEnum):
    """How the patcher finished with one finding.

    `VERIFIED` is the only outcome carrying something publishable, and it still is not "published"
    — posting is `apps/worker`'s, and whether it succeeded is recorded separately. A package that
    reported its own work as published would be reporting an intention.
    """

    VERIFIED = "verified"
    """A repair passed every rung and anchors inside the diff."""

    NOT_ANCHORABLE = "not_anchorable"
    """A repair passed every rung, but the lines it replaces are not all in this pull request's
    diff, so GitHub has nowhere to attach it (D-095)."""

    UNVERIFIED = "unverified"
    """Every draft was read and every one failed a check. The most interesting outcome there is:
    it means the model wrote something and this system disagreed."""

    NO_REPAIR_OFFERED = "no_repair_offered"
    """The model returned the function unchanged, which the prompt defines as "I have no repair".
    Not retried — asking the same question again is not new information."""

    PATCHER_UNAVAILABLE = "patcher_unavailable"
    """No model was configured, or every attempt failed before a draft could be read. The
    abstention of this subsystem: it says nothing about the code."""

    UNIT_TOO_LARGE = "unit_too_large"
    """Over `PatchConfig.max_unit_bytes`. Never truncated — a repair drafted from half a function
    is the D-015 failure with a commit button on it."""

    UNPARSEABLE_UNIT = "unparseable_unit"
    """The function under review does not parse, so there is no baseline to check a repair
    against. tree-sitter extracted it anyway, which is what tree-sitter is for."""

    DISABLED = "disabled"
    """Turned off by configuration. Reported rather than skipped, so a repository whose owner
    switched patching off does not look like one where the patcher failed."""

    NOT_ALERT_WORTHY = "not_alert_worthy"
    """Below the alert threshold, so no repair was requested (§2). Recorded for the findings that
    reach the patcher through a caller that decided not to ask."""


@dataclass(frozen=True)
class PatchProposal:
    """Everything one finding's pass through the patcher produced."""

    finding_key: str
    unit_id: str
    cwe: str
    outcome: ProposalOutcome
    detail: str = ""

    drafts_requested: int = 0
    verification: Verification | None = None
    replacement: LineReplacement | None = None
    anchor: Anchor | None = None

    patched_src: str | None = None
    """The repaired function. **In memory only — never persisted** (D-097).

    It is a copy of somebody else's source with our edit in it, and §6 keeps source out of the
    database. The place a patch belongs is the pull request it was drafted for, where the code
    already lives and its author already controls it.
    """

    @property
    def is_publishable(self) -> bool:
        return self.outcome is ProposalOutcome.VERIFIED and self.anchor is not None


def propose(
    unit: ChangeUnit,
    cwe: str,
    finding_key: str,
    model: PatchModel | None,
    config: PatchConfig,
    rechecks: tuple[Rechecker, ...] = (),
    detecting_witnesses: frozenset[str] = frozenset(),
    pre_existing_cwes: frozenset[str] = frozenset(),
) -> PatchProposal:
    """One finding in, one proposal out. Never raises."""
    cwe = cwe.strip().upper()

    def outcome(
        kind: ProposalOutcome,
        detail: str,
        drafts_requested: int = 0,
        verification: Verification | None = None,
        replacement: LineReplacement | None = None,
        anchor: Anchor | None = None,
        patched_src: str | None = None,
    ) -> PatchProposal:
        return PatchProposal(
            finding_key=finding_key,
            unit_id=unit.unit_id,
            cwe=cwe,
            outcome=kind,
            detail=detail,
            drafts_requested=drafts_requested,
            verification=verification,
            replacement=replacement,
            anchor=anchor,
            patched_src=patched_src,
        )

    if not config.enabled:
        return outcome(ProposalOutcome.DISABLED, "patch suggestions are switched off")
    if model is None:
        return outcome(
            ProposalOutcome.PATCHER_UNAVAILABLE,
            "no model is configured, so no repair was drafted",
        )

    unit_bytes = len(unit.post_src.encode("utf-8"))
    if unit_bytes > config.max_unit_bytes:
        return outcome(
            ProposalOutcome.UNIT_TOO_LARGE,
            f"the function is {unit_bytes} bytes, over the {config.max_unit_bytes} byte budget; "
            "it was not truncated",
        )
    if parse(unit.post_src) is None:
        return outcome(
            ProposalOutcome.UNPARSEABLE_UNIT,
            "the function under review does not parse, so a repair has no baseline to be "
            "checked against",
        )

    constraints: tuple[str, ...] = ()
    last_verification: Verification | None = None
    last_error = ""
    attempts = 0

    for attempt in range(1, max(1, config.max_drafts) + 1):
        attempts = attempt
        request = DraftRequest(unit=unit, cwe=cwe, constraints=constraints)
        try:
            patched_src = draft(model, request, config.temperature)
        except DraftUnavailableError as exc:
            # A transport or protocol failure, not a rejected repair — and the loop **stops**.
            #
            # The draft budget exists for repairs this system rejected, and the rejection reasons
            # are what make a second attempt different from the first. A model that could not be
            # reached has been told nothing, so the second request is identical to the first; and
            # the client already owns its own bounded retry policy (D-065), so repeating it here
            # multiplies one budget by the other — nine requests against a free tier for one
            # finding, each one costing its own backoff.
            last_error = str(exc)
            logger.warning("Patch draft %s for %s could not be read: %s", attempt, finding_key, exc)
            break

        replacement = line_replacement(unit.post_src, patched_src)
        if replacement is None:
            return outcome(
                ProposalOutcome.NO_REPAIR_OFFERED,
                "the model returned the function unchanged, which the prompt defines as "
                "offering no repair",
                drafts_requested=attempt,
            )

        verification = verify(
            VerificationRequest(
                unit=unit,
                patched_src=patched_src,
                cwe=cwe,
                rechecks=rechecks,
                detecting_witnesses=detecting_witnesses,
                pre_existing_cwes=pre_existing_cwes,
            )
        )
        last_verification = verification

        if not verification.verified:
            constraints = tuple(dict.fromkeys([*constraints, *verification.feedback]))
            logger.info(
                "Patch draft %s for %s did not verify: %s",
                attempt,
                finding_key,
                "; ".join(verification.feedback) or "no rechecker examined it",
            )
            continue

        anchor = anchor_for(unit, replacement)
        if anchor is None:
            start, end = replacement.absolute(unit.start_line)
            return outcome(
                ProposalOutcome.NOT_ANCHORABLE,
                f"the repair replaces lines {start}-{end}, which this pull request does not "
                "entirely change, so GitHub has nowhere to attach a suggestion",
                drafts_requested=attempt,
                verification=verification,
                replacement=replacement,
                patched_src=patched_src,
            )

        return outcome(
            ProposalOutcome.VERIFIED,
            f"verified across {len(verification.results)} check(s)",
            drafts_requested=attempt,
            verification=verification,
            replacement=replacement,
            anchor=anchor,
            patched_src=patched_src,
        )

    if last_verification is None:
        return outcome(
            ProposalOutcome.PATCHER_UNAVAILABLE,
            f"{attempts} draft(s) were requested and none could be read; last failure: "
            f"{last_error}",
            drafts_requested=attempts,
        )
    return outcome(
        ProposalOutcome.UNVERIFIED,
        "; ".join(last_verification.feedback) or "no witness re-examined the repaired function",
        drafts_requested=attempts,
        verification=last_verification,
    )
