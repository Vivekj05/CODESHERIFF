"""Wiring the patcher into an audit: who gets a draft, who rechecks, and what reaches GitHub.

`packages/patch` owns what a repair is and whether it holds up, and its own tests cover that. What
is only assertable here is the wiring: that the alert threshold decides who is asked, that the
recheckers are the deterministic witnesses from *this audit's* roster, and that a suggestion GitHub
refuses does not cost the audit its summary comment.
"""

from __future__ import annotations

import uuid

import pytest

from codesheriff_contracts import ChangeUnit, Evidence
from codesheriff_engine.fusion import (
    CONTEXT,
    RUNTIME,
    SEMANTIC,
    STRUCTURAL,
    FusionResult,
    Stance,
    WitnessContribution,
)
from codesheriff_patch import PatchConfig, ProposalOutcome
from codesheriff_worker.analysis import UnavailableAgent
from codesheriff_worker.patching import (
    RECHECKING_WITNESSES,
    PatchDeps,
    build_patch_model,
    detecting_witnesses,
    pre_existing_cwes,
    propose_for_unit,
    publish,
    rechecks_for,
)

VULNERABLE = (
    "    def lookup(self, user_id):\n"
    '        query = "SELECT * FROM users WHERE id = " + user_id\n'
    "        return self.cursor.execute(query).fetchone()"
)
REPAIRED = (
    "    def lookup(self, user_id):\n"
    '        query = "SELECT * FROM users WHERE id = ?"\n'
    "        return self.cursor.execute(query, (user_id,)).fetchone()"
)


class ScriptedModel:
    def __init__(self, answer: str) -> None:
        self.answer = answer
        self.calls = 0

    def complete(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
        self.calls += 1
        import json

        return json.dumps({"patched_function": self.answer})


class SilentAgent:
    """A witness that finds nothing. Stands in for a taint engine on a repaired function."""

    agent_id = "structural.taint"
    agent_version = "0.1.0"

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        return [
            Evidence.silence(
                agent_id=self.agent_id,
                agent_version=self.agent_version,
                unit_id=unit.unit_id,
                covered_cwes={"CWE-89"},
            )
        ]


class SemanticAgentStub:
    agent_id = "semantic.hosted"
    agent_version = "0.1.0"

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:  # pragma: no cover - never called
        raise AssertionError("the semantic witness must not be asked to recheck a patch")


@pytest.fixture
def unit() -> ChangeUnit:
    return ChangeUnit(
        unit_id="app/db.py::Users.lookup",
        repo="acme/app",
        language="python",
        file="app/db.py",
        symbol="lookup",
        enclosing_class="Users",
        post_src=VULNERABLE,
        start_line=10,
        changed_lines=[10, 11, 12],
        imports=["import sqlite3"],
        base_sha="a" * 40,
        head_sha="b" * 40,
    )


def a_finding(unit: ChangeUnit, posterior: float, alert: bool) -> FusionResult:
    return FusionResult(
        finding_key=unit.key_for("CWE-89"),
        posterior_probability=posterior,
        is_alert_worthy=alert,
        evidence_list=[],
        cwe="CWE-89",
        contributions=[
            WitnessContribution(witness=STRUCTURAL, stance=Stance.DETECTED, likelihood_ratio=8.5),
            WitnessContribution(witness=SEMANTIC, stance=Stance.SILENT, likelihood_ratio=0.4),
            WitnessContribution(witness=CONTEXT, stance=Stance.NEUTRAL, likelihood_ratio=1.0),
            WitnessContribution(witness=RUNTIME, stance=Stance.NEUTRAL, likelihood_ratio=1.0),
        ],
    )


def run_patcher(
    unit: ChangeUnit,
    result: FusionResult,
    model: object = None,
    evidence: list[Evidence] | None = None,
) -> list:
    return propose_for_unit(
        unit,
        [result],
        evidence or [],
        deps=PatchDeps(model=model, rechecks=rechecks_for([SilentAgent()])),  # type: ignore[arg-type]
        config=PatchConfig(enabled=True, max_drafts=3, temperature=0.2),
        finding_ids={result.finding_key: uuid.uuid4()},
    )


class TestWhoGetsADraft:
    def test_an_alert_worthy_finding_is_drafted_for(self, unit: ChangeUnit) -> None:
        model = ScriptedModel(REPAIRED)
        records = run_patcher(unit, a_finding(unit, 0.91, alert=True), model)
        assert model.calls == 1
        assert records[0].outcome is ProposalOutcome.VERIFIED

    def test_a_finding_below_the_threshold_is_recorded_but_never_drafted(
        self, unit: ChangeUnit
    ) -> None:
        # §2: the report fires on both paths. "We did not try" is a statement, not an absence.
        model = ScriptedModel(REPAIRED)
        records = run_patcher(unit, a_finding(unit, 0.12, alert=False), model)
        assert model.calls == 0
        assert records[0].outcome is ProposalOutcome.NOT_ALERT_WORTHY

    def test_no_model_records_the_patcher_s_own_abstention(self, unit: ChangeUnit) -> None:
        records = run_patcher(unit, a_finding(unit, 0.91, alert=True), model=None)
        assert records[0].outcome is ProposalOutcome.PATCHER_UNAVAILABLE

    def test_a_model_that_raises_is_the_patcher_abstaining(self, unit: ChangeUnit) -> None:
        class Exploding:
            def complete(self, system_prompt: str, user_prompt: str, temperature: float) -> str:
                raise ConnectionError("no route to host")

        records = run_patcher(unit, a_finding(unit, 0.91, alert=True), Exploding())
        assert records[0].outcome is ProposalOutcome.PATCHER_UNAVAILABLE
        assert "ConnectionError" in records[0].proposal.detail

    def test_a_patcher_that_raises_does_not_cost_the_audit(
        self, unit: ChangeUnit, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # `propose` documents that it never raises. This is the belt to that braces: an audit must
        # still produce its comment if the promise is ever broken.
        def explode(**kwargs: object) -> object:
            raise RuntimeError("the patcher fell over")

        monkeypatch.setattr("codesheriff_worker.patching.propose", explode)
        records = run_patcher(unit, a_finding(unit, 0.91, alert=True), ScriptedModel(REPAIRED))
        assert records[0].outcome is ProposalOutcome.PATCHER_UNAVAILABLE
        assert "RuntimeError" in records[0].proposal.detail

    def test_a_finding_that_was_not_persisted_gets_no_proposal(self, unit: ChangeUnit) -> None:
        result = a_finding(unit, 0.91, alert=True)
        records = propose_for_unit(
            unit,
            [result],
            [],
            deps=PatchDeps(model=ScriptedModel(REPAIRED)),
            config=PatchConfig(),
            finding_ids={},
        )
        assert records == []


class TestWhoRechecks:
    def test_only_the_deterministic_witnesses_recheck(self) -> None:
        rechecks = rechecks_for([SilentAgent(), SemanticAgentStub()])
        assert [r.witness for r in rechecks] == [STRUCTURAL]
        assert SEMANTIC not in RECHECKING_WITNESSES
        assert CONTEXT not in RECHECKING_WITNESSES

    def test_an_unloadable_witness_contributes_no_rechecker(self) -> None:
        # `UnavailableAgent` declares a registered id but abstains on everything. Including it
        # would produce a rung that is NOT_RUN on every patch, which is honest but useless; what
        # matters is that it is not silently counted as a pass.
        rechecks = rechecks_for(
            [SilentAgent(), UnavailableAgent("runtime.sfi", "agent_unavailable")]
        )
        assert [r.witness for r in rechecks] == [STRUCTURAL, RUNTIME]
        evidence = rechecks[1].analyse(
            ChangeUnit(
                unit_id="u",
                repo="r",
                language="python",
                file="f.py",
                post_src="x = 1",
                base_sha="a" * 40,
                head_sha="b" * 40,
            )
        )
        assert all(not e.is_detection for e in evidence)

    def test_an_agent_with_an_unregistered_id_is_skipped_rather_than_fatal(self) -> None:
        class Rogue:
            agent_id = "structural.experimental"

            def analyze(self, unit: ChangeUnit) -> list[Evidence]:  # pragma: no cover
                return []

        assert rechecks_for([Rogue()]) == ()


class TestWhatTheLadderIsToldAboutTheFinding:
    def test_detecting_witnesses_come_from_the_stored_contributions(self, unit: ChangeUnit) -> None:
        assert detecting_witnesses(a_finding(unit, 0.9, alert=True)) == frozenset({STRUCTURAL})

    def test_a_weakness_the_unit_already_had_is_carried_across(self, unit: ChangeUnit) -> None:
        evidence = [
            Evidence.detection(
                agent_id="structural.taint",
                agent_version="0.1.0",
                unit_id=unit.unit_id,
                finding_key=unit.key_for("CWE-78"),
                cwe="CWE-78",
                raw_score=0.8,
            )
        ]
        assert pre_existing_cwes(evidence, "CWE-89") == frozenset({"CWE-78"})
        assert pre_existing_cwes(evidence, "CWE-78") == frozenset()


class TestPublishing:
    def _publishable(self, unit: ChangeUnit) -> list:
        return run_patcher(unit, a_finding(unit, 0.91, alert=True), ScriptedModel(REPAIRED))

    def test_a_verified_repair_is_posted_as_an_anchored_suggestion(
        self, unit: ChangeUnit, gateway
    ) -> None:
        records = self._publishable(unit)
        publish(gateway, records, 42, "acme/app", 7, "https://dash/audits/1")

        assert len(gateway.review_comments) == 1
        posted = gateway.review_comments[0]
        assert (posted.start_line, posted.line) == (11, 12)
        assert posted.commit_sha == unit.head_sha
        assert posted.path == "app/db.py"
        assert "```suggestion" in posted.body
        assert records[0].published is True
        assert records[0].github_comment_id is not None

    def test_the_body_names_no_file(self, unit: ChangeUnit, gateway) -> None:
        # D-050. The path travels as an API field, never as rendered text.
        records = self._publishable(unit)
        publish(gateway, records, 42, "acme/app", 7, "https://dash/audits/1")
        assert "app/db.py" not in gateway.review_comments[0].body

    def test_a_refused_suggestion_is_recorded_and_never_raised(
        self, unit: ChangeUnit, gateway
    ) -> None:
        gateway.review_comments_fail = True
        records = self._publishable(unit)
        publish(gateway, records, 42, "acme/app", 7, "https://dash/audits/1")

        assert gateway.review_comments == []
        assert records[0].published is False
        assert records[0].publish_error
        # The outcome is still `verified`: the repair held up, and GitHub is what failed.
        assert records[0].outcome is ProposalOutcome.VERIFIED

    def test_nothing_is_posted_for_a_finding_with_no_repair(
        self, unit: ChangeUnit, gateway
    ) -> None:
        records = run_patcher(unit, a_finding(unit, 0.91, alert=True), model=None)
        publish(gateway, records, 42, "acme/app", 7, "https://dash/audits/1")
        assert gateway.review_comments == []


def test_no_model_is_built_without_a_key() -> None:
    """Never a stub. A stub that answered would produce a suggestion nobody's model wrote."""
    assert build_patch_model(PatchConfig(api_key=None, enabled=True)) is None
    assert build_patch_model(PatchConfig(api_key="k", enabled=False)) is None
