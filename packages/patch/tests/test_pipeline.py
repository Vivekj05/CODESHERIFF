"""Draft → verify → retry, and every way it stops."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from codesheriff_contracts import ChangeUnit, Evidence
from codesheriff_patch.config import PatchConfig
from codesheriff_patch.drafting import PatchModel
from codesheriff_patch.pipeline import PatchProposal, ProposalOutcome, propose
from codesheriff_patch.verify import Rechecker

STRUCTURAL = "structural"


def config(enabled: bool = True, max_drafts: int = 3, max_unit_bytes: int = 24_000) -> PatchConfig:
    return PatchConfig(
        enabled=enabled,
        max_drafts=max_drafts,
        max_unit_bytes=max_unit_bytes,
        temperature=0.2,
    )


def silent(unit: ChangeUnit) -> Rechecker:
    def analyse(u: ChangeUnit) -> list[Evidence]:
        return [
            Evidence.silence(
                agent_id="structural.taint",
                agent_version="0.1.0",
                unit_id=u.unit_id,
                covered_cwes={"CWE-89"},
            )
        ]

    return Rechecker(witness=STRUCTURAL, analyse=analyse)


def still_detecting(unit: ChangeUnit) -> Rechecker:
    def analyse(u: ChangeUnit) -> list[Evidence]:
        return [
            Evidence.detection(
                agent_id="structural.taint",
                agent_version="0.1.0",
                unit_id=u.unit_id,
                finding_key=u.key_for("CWE-89"),
                cwe="CWE-89",
                raw_score=0.9,
            )
        ]

    return Rechecker(witness=STRUCTURAL, analyse=analyse)


def run(
    unit: ChangeUnit,
    model: PatchModel | None,
    patch_config: PatchConfig | None = None,
    rechecks: tuple[Rechecker, ...] | None = None,
) -> PatchProposal:
    return propose(
        unit=unit,
        cwe="CWE-89",
        finding_key=unit.key_for("CWE-89"),
        model=model,
        config=patch_config or config(),
        rechecks=rechecks if rechecks is not None else (silent(unit),),
        detecting_witnesses=frozenset({STRUCTURAL}),
    )


class TestTheHappyPath:
    def test_a_verified_anchorable_repair_is_publishable(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        model = scripted([response_for(repaired)])
        proposal = run(unit, model)
        assert proposal.outcome is ProposalOutcome.VERIFIED
        assert proposal.is_publishable
        assert proposal.drafts_requested == 1
        assert proposal.anchor is not None

    def test_it_asks_the_model_once_when_the_first_draft_holds(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        model = scripted([response_for(repaired)])
        run(unit, model)
        assert len(model.prompts) == 1


class TestRetry:
    def test_a_rejected_draft_is_retried_with_the_reason_and_not_the_draft(
        self,
        unit: ChangeUnit,
        repaired: str,
        indent_like_a_file: Callable[..., str],
        scripted: Any,
        response_for: Callable[[str], str],
    ) -> None:
        # D-093. The rejected draft is model output shaped by attacker-controlled source; feeding
        # it back as instruction would move untrusted text outside the sentinel.
        widened = indent_like_a_file(
            """
            def lookup(self, user_id, safe=True):
                return self.cursor.execute("SELECT 1", (user_id,)).fetchone()
            """,
            indent=4,
        )
        model = scripted([response_for(widened), response_for(repaired)])
        proposal = run(unit, model)

        assert proposal.outcome is ProposalOutcome.VERIFIED
        assert proposal.drafts_requested == 2
        second = model.prompts[1]
        assert "signature changed" in second
        assert "safe=True" not in second

    def test_it_gives_up_after_the_configured_number_of_drafts(
        self, unit: ChangeUnit, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        model = scripted([response_for("def lookup(self, user_id:")])
        proposal = run(unit, model)
        assert proposal.outcome is ProposalOutcome.UNVERIFIED
        assert proposal.drafts_requested == 3
        assert len(model.prompts) == 3

    def test_constraints_accumulate_rather_than_replace(
        self,
        unit: ChangeUnit,
        repaired: str,
        indent_like_a_file: Callable[..., str],
        scripted: Any,
        response_for: Callable[[str], str],
    ) -> None:
        reaching = indent_like_a_file(
            """
            def lookup(self, user_id):
                return self.cursor.execute("SELECT 1", (shlex.quote(user_id),)).fetchone()
            """,
            indent=4,
        )
        widened = indent_like_a_file(
            """
            def lookup(self, user_id, safe=True):
                return self.cursor.execute("SELECT 1", (user_id,)).fetchone()
            """,
            indent=4,
        )
        model = scripted([response_for(reaching), response_for(widened), response_for(repaired)])
        proposal = run(unit, model)
        assert proposal.outcome is ProposalOutcome.VERIFIED
        third = model.prompts[2]
        assert "shlex" in third
        assert "signature changed" in third

    def test_a_still_detected_weakness_is_a_rejection_the_model_is_told_about(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        model = scripted([response_for(repaired)])
        proposal = run(unit, model, rechecks=(still_detecting(unit),))
        assert proposal.outcome is ProposalOutcome.UNVERIFIED
        assert "still detects CWE-89" in proposal.detail


class TestStoppingWithoutAPatch:
    def test_an_unchanged_function_means_no_repair_and_is_not_retried(
        self, unit: ChangeUnit, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        model = scripted([response_for(unit.post_src)])
        proposal = run(unit, model)
        assert proposal.outcome is ProposalOutcome.NO_REPAIR_OFFERED
        assert len(model.prompts) == 1

    def test_no_model_is_a_patcher_that_could_not_run(self, unit: ChangeUnit) -> None:
        proposal = run(unit, None)
        assert proposal.outcome is ProposalOutcome.PATCHER_UNAVAILABLE

    def test_every_draft_failing_to_arrive_is_unavailable_not_unverified(
        self, unit: ChangeUnit, scripted: Any
    ) -> None:
        # A transport failure says nothing about the code, and must not be recorded as three
        # repairs this system rejected.
        model = scripted([ConnectionError("no route to host")])
        proposal = run(unit, model)
        assert proposal.outcome is ProposalOutcome.PATCHER_UNAVAILABLE
        assert "ConnectionError" in proposal.detail
        assert proposal.drafts_requested == 1

    def test_a_transport_failure_ends_the_loop_rather_than_re_asking(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        # The model was told nothing, so a second request would be identical to the first — and
        # the client already owns a bounded retry policy of its own (D-065). Retrying here
        # multiplies one budget by the other against a free tier.
        model = scripted([ConnectionError("boom"), response_for(repaired)])
        proposal = run(unit, model)
        assert proposal.outcome is ProposalOutcome.PATCHER_UNAVAILABLE
        assert len(model.prompts) == 1

    def test_an_oversized_function_is_declined_rather_than_truncated(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        model = scripted([response_for(repaired)])
        proposal = run(unit, model, patch_config=config(max_unit_bytes=10))
        assert proposal.outcome is ProposalOutcome.UNIT_TOO_LARGE
        assert model.prompts == []

    def test_a_function_that_does_not_parse_has_no_baseline(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        broken = unit.model_copy(update={"post_src": "    def lookup(self, user_id:"})
        model = scripted([response_for(repaired)])
        proposal = run(broken, model)
        assert proposal.outcome is ProposalOutcome.UNPARSEABLE_UNIT
        assert model.prompts == []

    def test_switched_off_is_reported_rather_than_skipped(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        model = scripted([response_for(repaired)])
        proposal = run(unit, model, patch_config=config(enabled=False))
        assert proposal.outcome is ProposalOutcome.DISABLED
        assert model.prompts == []

    def test_a_verified_repair_outside_the_diff_is_not_published_and_not_re_drafted(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        # Where a repair lands is a property of the pull request's diff, not of the draft's
        # quality; re-drafting against it would be searching for a patch that fits the hunk.
        narrowed = unit.model_copy(update={"changed_lines": [10]})
        model = scripted([response_for(repaired)])
        proposal = propose(
            unit=narrowed,
            cwe="CWE-89",
            finding_key=narrowed.key_for("CWE-89"),
            model=model,
            config=config(),
            rechecks=(silent(narrowed),),
            detecting_witnesses=frozenset({STRUCTURAL}),
        )
        assert proposal.outcome is ProposalOutcome.NOT_ANCHORABLE
        assert not proposal.is_publishable
        assert len(model.prompts) == 1
        assert proposal.verification is not None and proposal.verification.verified


class TestItNeverRaises:
    def test_a_model_that_returns_nonsense_produces_a_proposal_not_an_exception(
        self, unit: ChangeUnit, scripted: Any
    ) -> None:
        model = scripted(["not json at all"])
        proposal = run(unit, model)
        assert proposal.outcome is ProposalOutcome.PATCHER_UNAVAILABLE

    def test_the_repaired_source_never_leaves_the_proposal_object(
        self, unit: ChangeUnit, repaired: str, scripted: Any, response_for: Callable[[str], str]
    ) -> None:
        # D-097: it is in memory for as long as it takes to post a suggestion, and nowhere else.
        model = scripted([response_for(repaired)])
        proposal = run(unit, model)
        assert proposal.patched_src == repaired
        # Nothing on the proposal is a serialisable record carrying it: the storage mapping reads
        # `outcome`, `drafts_requested` and the check names, and hashes the rest.
        assert proposal.verification is not None
        assert all(repaired not in result.detail for result in proposal.verification.results)
