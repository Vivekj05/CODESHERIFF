"""Driving the patcher, and posting what it produced.

`codesheriff_patch` decides what a repair is and whether it holds up. This decides who gets one,
supplies the model and the witnesses it declares protocols for, and writes the result to GitHub —
the same division `analysis.py` keeps with the agents, and for the same reason (D-054, D-072). The
package is testable with no key and no network because none of this is inside it.

**Only alert-worthy findings get a draft** (§2). The threshold is the one stamped on the audit row
when it was opened, not today's artifact, so a finding below the line records `not_alert_worthy`
rather than nothing at all: the pull request comment reports on both paths, and "we did not try"
is a different statement from "we tried and failed".

**Two witnesses recheck, not four.** `structural` and `runtime` decide from the code alone, so
their answer about a repaired function is reproducible. `semantic` is excluded because re-asking a
hosted model whether the repair it drafted is a repair is the drafter's own family grading the
drafter, and because a non-deterministic rung would make the same draft publishable on one run and
not on the next. `context` is excluded because its basis is the repository's merged history, which
a proposed patch is not part of — it would answer about the original function every time.

**Suggestions only. Nothing here commits, merges or pushes** (§2). The only write is a review
comment carrying a fenced `suggestion` block, which a human applies or does not.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field

from codesheriff_contracts import ChangeUnit, Evidence, EvidenceKind
from codesheriff_engine.fusion import RUNTIME, STRUCTURAL, FusionResult, Stance, witness_for
from codesheriff_patch import (
    PatchConfig,
    PatchModel,
    PatchProposal,
    ProposalOutcome,
    Rechecker,
    propose,
)
from codesheriff_patch import render as render_suggestion
from codesheriff_worker.analysis import Agent, agent_id_of
from codesheriff_worker.github_gateway import GitHubError, GitHubGateway

logger = logging.getLogger(__name__)

RECHECKING_WITNESSES: tuple[str, ...] = (STRUCTURAL, RUNTIME)
"""The witnesses whose answer about a repaired function is a function of the code alone.

Ordered as `WITNESSES` orders them, so a published ladder reads the same way twice."""


@dataclass
class PatchRecord:
    """One finding's pass through the patcher, plus what became of it on GitHub.

    Mutable, unusually for this codebase, because publishing happens after the supersede check and
    updates the same record the analysis produced. The alternative is a second parallel list keyed
    by finding id, which is one more thing to get out of step.
    """

    finding_id: uuid.UUID
    proposal: PatchProposal
    published: bool = False
    github_comment_id: int | None = None
    publish_error: str = ""

    @property
    def outcome(self) -> ProposalOutcome:
        return self.proposal.outcome


@dataclass(frozen=True)
class PatchDeps:
    """What the patcher needs from this process. Empty is a valid state.

    With no model, every finding records `patcher_unavailable` — the patcher's abstention, which
    says nothing about the code and is reported as such rather than being read as "nothing to fix".
    """

    model: PatchModel | None = None
    rechecks: tuple[Rechecker, ...] = field(default_factory=tuple)


class GeminiPatchModel:
    """`semantic_agent`'s Gemini client, wearing the `PatchModel` protocol.

    The adapter exists so `codesheriff_patch` can declare what it needs in two prompts and a
    string, rather than depending on a client whose signature carries a response schema it never
    sends and a seed it does not want. It also keeps the patcher out of the agent packages
    entirely, which `lint-imports` enforces.
    """

    def __init__(self, api_key: str, model: str) -> None:
        from semantic_agent.llm.hosted import HostedLLMClient

        self._client = HostedLLMClient(api_key=api_key, model=model)

    def complete(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        from pydantic import BaseModel

        class PatchedFunction(BaseModel):
            patched_function: str

        return self._client.generate(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            schema=PatchedFunction,
            temperature=temperature,
        )


def build_patch_model(config: PatchConfig) -> PatchModel | None:
    """The model the patcher drafts with, or None.

    None is the ordinary state on a machine with no key, and it is not an error: the finding still
    gets a row and the comment still says a suggestion was not attempted.
    """
    if not config.enabled or not config.api_key:
        return None
    try:
        return GeminiPatchModel(api_key=config.api_key, model=config.model)
    except Exception as exc:
        logger.warning("No patch model could be built: %s", exc)
        return None


def rechecks_for(agents: list[Agent]) -> tuple[Rechecker, ...]:
    """Recheckers for the deterministic witnesses in this audit's roster.

    Built from the agents the audit actually loaded, so a patch is rechecked by the same objects
    that produced the finding — including their configuration. Constructing fresh agents here would
    let a repair be judged by a differently configured witness than the one that accused it.
    """
    by_witness: dict[str, Agent] = {}
    for agent in agents:
        agent_id = agent_id_of(agent, "")
        try:
            witness = witness_for(agent_id)
        except Exception:
            continue
        if witness in RECHECKING_WITNESSES:
            by_witness.setdefault(witness, agent)

    return tuple(
        Rechecker(witness=witness, analyse=by_witness[witness].analyze)
        for witness in RECHECKING_WITNESSES
        if witness in by_witness
    )


def detecting_witnesses(result: FusionResult) -> frozenset[str]:
    """Witnesses that detected this finding, read from the fused contributions.

    From `contributions` rather than from the evidence, because that list is the run's own record
    of what each witness's statements amounted to after its backends were combined (D-011). Reading
    the evidence again here would be a second implementation of the same question.
    """
    return frozenset(c.witness for c in result.contributions if c.stance is Stance.DETECTED)


def pre_existing_cwes(evidence: list[Evidence], cwe: str) -> frozenset[str]:
    """Other in-scope weaknesses already detected in this unit.

    Excluded from the patch's `no_new_weakness` rung: a repair is not answerable for a second
    weakness that was there before it, and blaming it would reject every repair to a function with
    two problems.
    """
    target = cwe.strip().upper()
    return frozenset(
        (ev.cwe or "").strip().upper()
        for ev in evidence
        if ev.kind is EvidenceKind.DETECTION and (ev.cwe or "").strip().upper() != target
    )


def propose_for_unit(
    unit: ChangeUnit,
    results: list[FusionResult],
    evidence: list[Evidence],
    deps: PatchDeps,
    config: PatchConfig,
    finding_ids: dict[str, uuid.UUID],
) -> list[PatchRecord]:
    """A record for every persisted finding of one unit. Never raises.

    A finding below the alert threshold is recorded `not_alert_worthy` without a model call, so the
    table says why there is no suggestion rather than holding no row.
    """
    records: list[PatchRecord] = []
    for result in results:
        finding_id = finding_ids.get(result.finding_key)
        if finding_id is None or not result.cwe:
            # Both are "should not happen": the caller passes the findings it persisted, and a
            # persistable finding carries a CWE. Logged rather than passed over in silence —
            # a proposal that vanishes without trace is how the patcher would come to look
            # like a patcher nobody ever invokes.
            logger.warning(
                "No patch proposal for finding %s: %s",
                result.finding_key,
                "it was not persisted" if finding_id is None else "it carries no CWE",
            )
            continue

        if not result.is_alert_worthy:
            records.append(
                PatchRecord(
                    finding_id=finding_id,
                    proposal=PatchProposal(
                        finding_key=result.finding_key,
                        unit_id=unit.unit_id,
                        cwe=result.cwe.strip().upper(),
                        outcome=ProposalOutcome.NOT_ALERT_WORTHY,
                        detail=(
                            "the posterior is below this audit's alert threshold, so no repair "
                            "was requested"
                        ),
                    ),
                )
            )
            continue

        try:
            proposal = propose(
                unit=unit,
                cwe=result.cwe,
                finding_key=result.finding_key,
                model=deps.model,
                config=config,
                rechecks=deps.rechecks,
                detecting_witnesses=detecting_witnesses(result),
                pre_existing_cwes=pre_existing_cwes(evidence, result.cwe),
            )
        except Exception as exc:
            # `propose` documents that it never raises; this is the belt to that braces. A patcher
            # that fell over must not cost the audit its comment.
            logger.exception("Patcher raised on finding %s", result.finding_key)
            proposal = PatchProposal(
                finding_key=result.finding_key,
                unit_id=unit.unit_id,
                cwe=result.cwe.strip().upper(),
                outcome=ProposalOutcome.PATCHER_UNAVAILABLE,
                detail=f"{type(exc).__name__}: {exc}"[:400],
            )

        logger.info(
            "Patch for %s (%s): %s — %s",
            result.finding_key,
            result.cwe,
            proposal.outcome.value,
            proposal.detail,
        )
        records.append(PatchRecord(finding_id=finding_id, proposal=proposal))
    return records


def publish(
    gateway: GitHubGateway,
    records: list[PatchRecord],
    installation_id: int,
    repo_full_name: str,
    pr_number: int,
    dashboard_url: str,
) -> None:
    """Post each publishable suggestion, recording on the record whether it landed.

    A failure to post is written to the record and never raised. The audit's summary comment is
    worth more than any one suggestion, and losing it because GitHub rejected a line anchor would
    trade the whole review for a single fix.
    """
    for record in records:
        proposal = record.proposal
        if not proposal.is_publishable:
            continue
        assert proposal.anchor is not None and proposal.replacement is not None
        assert proposal.verification is not None

        body = render_suggestion(
            proposal.cwe, proposal.replacement, proposal.verification, dashboard_url
        )
        try:
            record.github_comment_id = gateway.post_review_comment(
                installation_id=installation_id,
                repo_full_name=repo_full_name,
                pr_number=pr_number,
                commit_sha=proposal.anchor.commit_sha,
                path=proposal.anchor.path,
                start_line=proposal.anchor.start_line,
                line=proposal.anchor.line,
                body=body,
            )
            record.published = True
        except GitHubError as exc:
            record.publish_error = str(exc)
            logger.warning(
                "Could not post the suggestion for %s on %s#%s: %s",
                proposal.finding_key,
                repo_full_name,
                pr_number,
                exc,
            )
