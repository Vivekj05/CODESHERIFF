"""The calibration harness: what it refuses, and what it records.

The arithmetic is tested in `packages/engine`. What is tested here is the part that could
quietly invalidate every number the arithmetic produces — reading the wrong split, replaying
the wrong response, or fitting against a corpus that has changed since it was observed. None
of those would raise on their own; each would produce a plausible artifact describing a
measurement that never happened.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codesheriff_contracts import Evidence
from codesheriff_corpus.models import Split
from codesheriff_engine.calibration.observations import ObservationSet, claims_for_case
from codesheriff_engine.fusion.cells import RatioCell
from codesheriff_worker.calibration import fitting, runner
from codesheriff_worker.calibration.responses import Recording, ReplayClient, ResponseStore

UNIT = "u1"


def detection(agent_id: str, cwe: str, key: str, score: float = 0.9) -> Evidence:
    return Evidence.detection(
        agent_id=agent_id,
        agent_version="1.0.0",
        unit_id=UNIT,
        finding_key=key,
        cwe=cwe,
        raw_score=score,
        explanation="found",
    )


def silence(agent_id: str, covered: set[str]) -> Evidence:
    return Evidence.silence(
        agent_id=agent_id,
        agent_version="1.0.0",
        unit_id=UNIT,
        covered_cwes=covered,
        explanation="looked, nothing",
    )


def abstention(agent_id: str, reason: str = "tool_unavailable") -> Evidence:
    return Evidence.abstention(
        agent_id=agent_id,
        agent_version="1.0.0",
        unit_id=UNIT,
        reason=reason,
        explanation="could not run",
    )


# -- the splits ---------------------------------------------------------------------------------


def test_the_test_split_cannot_be_observed() -> None:
    """§6 permits it exactly once, at the end, and Chapter 18 is the end.

    Refused by name rather than by convention: a harness that would run on the test split if
    asked is a harness that eventually will be.
    """
    with pytest.raises(runner.TestSplitSealedError, match="exactly once"):
        runner.cases_in_split(Split.TEST)


def test_calibration_and_validation_are_both_available() -> None:
    assert runner.cases_in_split(Split.CALIBRATION)
    assert runner.cases_in_split(Split.VALIDATION)


def test_fitting_refuses_observation_sets_from_the_wrong_split() -> None:
    """Fitting ratios on validation, or selecting a threshold on calibration, is the §6
    violation this chapter is most able to commit by accident."""
    calibration = runner.read(Split.CALIBRATION)
    validation = runner.read(Split.VALIDATION)

    with pytest.raises(ValueError, match="expected the calibration split"):
        fitting.fit_from_observations(validation, validation)
    with pytest.raises(ValueError, match="expected the validation split"):
        fitting.fit_from_observations(calibration, calibration)


def test_observations_recorded_against_another_corpus_are_refused(tmp_path: Path) -> None:
    """A stale observation file would produce an artifact whose recorded hash describes ground
    truth it was never measured against — the one thing the hash exists to prevent (D-045)."""
    observed = runner.read(Split.CALIBRATION)
    stale = observed.model_copy(update={"corpus_hash": "0" * 64})
    path = tmp_path / "calibration.jsonl"
    stale.to_jsonl(path)

    reloaded = ObservationSet.from_jsonl(path)
    assert reloaded.corpus_hash == "0" * 64

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(runner, "OBSERVATIONS_DIR", tmp_path)
        with pytest.raises(ValueError, match="re-observe"):
            runner.read(Split.CALIBRATION)


# -- claims -------------------------------------------------------------------------------------


def test_a_case_always_produces_its_own_claim_even_when_nobody_spoke() -> None:
    """The observation that makes a silence ratio mean anything.

    A vulnerable case every witness stayed silent on is a *missed* detection, and dropping it
    would fit `silence` only from cases where somebody spoke — the one population it is never
    applied to.
    """
    claims = claims_for_case(
        case_id="c1",
        pair_id="p1",
        split="calibration",
        cwe="CWE-89",
        finding_key="key-89",
        label_vulnerable=True,
        evidence=[
            silence("structural.taint", {"CWE-89"}),
            abstention("semantic.hosted"),
        ],
        key_for=lambda cwe: f"key-{cwe[-2:]}",
    )

    assert len(claims) == 1
    claim = claims[0]
    assert claim.label is True
    assert claim.is_primary
    assert claim.cell("structural") is RatioCell.SILENCE
    assert claim.cell("semantic") is None, "an abstention is not a cell"


def test_a_witness_silent_about_other_cwes_contributes_no_cell() -> None:
    """D-006. The taint engine holds no CWE-862 rules, and counting its silence there would
    fit a number from a witness that was never looking."""
    claims = claims_for_case(
        case_id="c1",
        pair_id="p1",
        split="calibration",
        cwe="CWE-862",
        finding_key="key-62",
        label_vulnerable=True,
        evidence=[silence("structural.taint", {"CWE-89", "CWE-79"})],
        key_for=lambda cwe: f"key-{cwe[-2:]}",
    )

    assert claims[0].cell("structural") is None


def test_a_detection_of_another_cwe_becomes_its_own_false_claim() -> None:
    """What a developer is actually shown is findings, not cases.

    A witness reporting CWE-79 on a pair written about CWE-89 has produced a finding no ground
    truth supports, and the threshold sweep has to score it as the false positive it is.
    """
    claims = claims_for_case(
        case_id="c1",
        pair_id="p1",
        split="calibration",
        cwe="CWE-89",
        finding_key="key-89",
        label_vulnerable=True,
        evidence=[
            detection("structural.taint", "CWE-89", "key-89"),
            detection("semantic.hosted", "CWE-79", "key-79"),
        ],
        key_for=lambda cwe: f"key-{cwe[-2:]}",
    )

    assert len(claims) == 2
    primary, spurious = claims[0], claims[1]

    assert primary.cwe == "CWE-89"
    assert primary.label is True
    assert primary.cell("structural") is RatioCell.DETECTION_HIGH
    assert primary.cell("semantic") is None, "a detection of another CWE says nothing here"

    assert spurious.cwe == "CWE-79"
    assert spurious.label is False, "the corpus says what this pair is about"
    assert spurious.is_primary is False
    assert spurious.cell("semantic") is RatioCell.DETECTION_HIGH


def test_two_backends_behind_one_witness_produce_one_cell() -> None:
    """D-011, at the point where observations are counted.

    Two structural backends both firing is one witness making one statement. If the fit
    counted it as two, the ratio it produced would describe a witness that does not exist.
    """
    claims = claims_for_case(
        case_id="c1",
        pair_id="p1",
        split="calibration",
        cwe="CWE-89",
        finding_key="key-89",
        label_vulnerable=True,
        evidence=[
            detection("structural.taint", "CWE-89", "key-89", score=0.6),
            detection("structural.semgrep", "CWE-89", "key-89", score=0.95),
        ],
        key_for=lambda cwe: f"key-{cwe[-2:]}",
    )

    assert len(claims) == 1
    # The strongest tier wins, exactly as `bayes._contribution` takes the max ratio.
    assert claims[0].cell("structural") is RatioCell.DETECTION_HIGH


# -- replay -------------------------------------------------------------------------------------


def test_replay_returns_the_samples_in_the_order_they_were_recorded() -> None:
    """Self-consistency reads the spread between samples; replaying one answer three times
    would look like unanimous confidence."""
    client = ReplayClient()
    client.bind(
        Recording(
            case_id="c1",
            model="m",
            prompt_fingerprint="f",
            samples=("a", "b", "c"),
            source="test",
        )
    )

    got = [client.generate("sys", "user", object()) for _ in range(3)]
    assert got == ["a", "b", "c"]


def test_a_case_with_no_recording_refuses_rather_than_answering_nothing() -> None:
    """Not a stub. A stub answers `{"findings": []}`, which the agent reports as SILENCE
    across every in-scope CWE — a witness that read nothing arguing the code is safe
    (`AUDIT.md` 3.12). Refusing produces an abstention, which costs the posterior nothing.
    """
    from semantic_agent.llm.hosted import ProviderUnavailableError

    client = ReplayClient()
    client.bind(None)

    with pytest.raises(ProviderUnavailableError, match="no recorded response"):
        client.generate("sys", "user", object())


def test_the_store_reports_where_each_answer_came_from() -> None:
    """Provenance, not decoration: a fit whose semantic witness was replayed from a different
    directory than it claims cannot be reproduced by the next person."""
    store = ResponseStore()
    cases = runner.cases_in_split(Split.VALIDATION)
    counts = store.sources(cases)

    assert counts["missing"] == 0, (
        "some validation cases have no recorded model response; the semantic witness would "
        "abstain across them and the threshold would be selected on a three-witness posterior"
    )
    assert counts["harness"] == len(cases)


# -- the artifact is what the observations say -------------------------------------------------


def test_refitting_the_committed_observations_reproduces_the_committed_artifact() -> None:
    """The Chapter 14 acceptance criterion, end to end.

    "`calibration.json` is reproducible from its recorded corpus hash." The corpus hash is
    checked against the live corpus in `packages/engine/tests/test_calibration_artifact.py`;
    this is the other half — that re-running the fit over the committed observations produces
    the same numbers the committed artifact carries.

    It is the test that would catch a hand-edited ratio, a fitting change nobody re-fitted
    after, and an artifact copied from a different machine. `generated` is expected to differ:
    it records when the fit ran, not what it found.
    """
    from codesheriff_engine.calibration import active_artifact

    committed = active_artifact()
    refitted = fitting.fit_from_observations(
        runner.read(Split.CALIBRATION),
        runner.read(Split.VALIDATION),
        base_rate=committed.prior.base_rate,
    )

    assert refitted.corpus_hash == committed.corpus_hash
    assert refitted.split_hash == committed.split_hash
    assert refitted.fit == committed.fit
    assert refitted.prior == committed.prior
    assert refitted.threshold == committed.threshold
    assert refitted.metrics == committed.metrics
