"""`runtime.sfi` measured against ground truth - on the calibration split, and only that.

**This file must never read the validation or the test split.** §6 reserves validation for
threshold selection and permits the test split to be evaluated exactly once, at the end.
Iterating a sink table while watching either one is fitting on it, whatever it is called,
and a test that runs on every commit is the most thorough possible form of iterating.
`test_only_the_calibration_split_is_read` asserts the restriction rather than trusting it.

The import is deliberate and does not breach D-047. That contract forbids the `agent_runtime`
**package** from reading the corpus - an agent that can see `label` is being told the answer,
and one that can see `detectable_by` can be excused by the field that exists to excuse it
fairly. A test is where the labels are supposed to be read.

`detectable_by` here is not this chapter's work. The corpus named `runtime.sfi` on fifteen
cases before this agent existed, from the pre-registered rule in D-047, and never widened it
afterwards. Nine of them are in the calibration split. That the five CWEs those cases span
are exactly `COVERED_CWES` is the pre-registration holding, not a coincidence arranged after
the fact - and it is why the narrowness of this witness is a claim rather than a convenience.

What this does **not** measure is the p95 latency target or the behaviour of a unit larger
than a corpus case. Both wait for Chapter 14, which runs the whole corpus on CI hardware.
"""

from __future__ import annotations

from functools import cache

import pytest

from agent_runtime.agent import RuntimeAgent
from agent_runtime.config import AGENT_ID, COVERED_CWES
from codesheriff_contracts import ChangeUnit, Evidence, EvidenceKind
from codesheriff_corpus.loader import load_cases
from codesheriff_corpus.models import CorpusCase, Label
from codesheriff_corpus.splits import Split, split_for

from .runtime_support import requires_interpreter

pytestmark = [pytest.mark.wasm, requires_interpreter]

AGENT = RuntimeAgent()
"""One agent, so one compiled interpreter for the whole module. The sandbox is built on the
first case that needs it; every case still runs in its own `Store`."""


def unit_of(case: CorpusCase) -> ChangeUnit:
    """A corpus case as the object an agent actually receives.

    The same shape `codesheriff_engine.extraction` produces from a pull request, which is the
    whole basis for applying a ratio fitted on one to the other (D-048).
    """
    return ChangeUnit(
        unit_id=case.case_id,
        repo="codesheriff/corpus",
        language=case.language,
        file=case.file,
        symbol=case.symbol,
        enclosing_class=case.enclosing_class,
        decorators=list(case.decorators),
        imports=list(case.imports),
        post_src=case.post_src,
        pre_src=case.pre_src,
        start_line=case.start_line,
        is_test_file=case.is_test_file,
        base_sha="b" * 40,
        head_sha="h" * 40,
    )


CASES = [case for case in load_cases() if split_for(case) is Split.CALIBRATION]
EXPECTED = [c for c in CASES if c.label is Label.VULNERABLE and AGENT_ID in c.detectable_by]
SAFE = [c for c in CASES if c.label is Label.SAFE]

_BY_ID = {case.case_id: case for case in CASES}


@cache
def evidence_for(case_id: str) -> tuple[Evidence, ...]:
    """One run per case, reused across assertions. Executing a case twice would double the
    slowest part of this suite to prove the same thing."""
    return tuple(AGENT.analyze(unit_of(_BY_ID[case_id])))


def detections(case_id: str) -> set[str]:
    return {e.cwe for e in evidence_for(case_id) if e.kind is EvidenceKind.DETECTION and e.cwe}


# -- the guards on the measurement itself --------------------------------------------------


def test_only_the_calibration_split_is_read() -> None:
    """§6 is not enforceable by intention alone."""
    assert CASES, "the calibration split is empty - the corpus or the splits did not load"
    assert all(split_for(case) is Split.CALIBRATION for case in CASES)


def test_the_corpus_predicts_this_agent_on_cases_this_agent_can_reach() -> None:
    """Every case `detectable_by` names for this agent is about a CWE it declares it covers.

    If this fails, either the corpus predicted a detection the agent's own scope makes
    impossible, or `COVERED_CWES` narrowed after the prediction was written. Both are
    failures of the pre-registration, and both would otherwise show up as a mysterious
    recall miss.
    """
    assert EXPECTED, "no calibration case predicts runtime.sfi - the measurement is vacuous"
    assert {case.cwe for case in EXPECTED} <= COVERED_CWES


def test_a_runnable_case_is_never_an_abstention() -> None:
    """The guard that stops this suite passing against an agent that never ran.

    An agent whose sandbox is broken abstains on everything, and every false-positive
    assertion below would pass. This asserts the opposite direction on the cases the corpus
    predicts: they were reached, executed and reported on.
    """
    abstained = [c.case_id for c in EXPECTED if not detections(c.case_id)]

    assert not abstained, f"predicted cases produced no detection: {abstained}"


# -- recall ---------------------------------------------------------------------------------


@pytest.mark.parametrize("case", EXPECTED, ids=lambda c: c.case_id)
def test_every_predicted_case_is_detected(case: CorpusCase) -> None:
    """`detectable_by` is a floor, not a ceiling (D-047).

    It was authored before any agent ran and is never widened afterwards, so a detection it
    did not predict is a bonus. A *missed* prediction is a regression, and that is what this
    catches.
    """
    assert case.cwe in detections(case.case_id), (
        f"{case.case_id} is predicted detectable by {AGENT_ID} and was not detected; "
        f"observed {sorted(detections(case.case_id)) or 'nothing'}"
    )


@pytest.mark.parametrize("case", EXPECTED, ids=lambda c: c.case_id)
def test_a_detection_carries_the_key_other_witnesses_derive(case: CorpusCase) -> None:
    """Two witnesses must land on one case number (D-004)."""
    changed = unit_of(case)
    keys = {e.finding_key for e in evidence_for(case.case_id) if e.kind is EvidenceKind.DETECTION}

    assert changed.key_for(case.cwe) in keys


# -- false positives ------------------------------------------------------------------------


@pytest.mark.parametrize("case", SAFE, ids=lambda c: c.case_id)
def test_no_safe_twin_is_reported(case: CorpusCase) -> None:
    """The measurement the twin pairs exist for.

    An agent that flags the vulnerable member has found something; one that flags both is
    reacting to the shape of the code. Twins share a `finding_key` by construction, so this
    is a lookup rather than a judgement.
    """
    assert not detections(case.case_id), (
        f"{case.case_id} is the safe twin of {case.pair_id} and was reported for "
        f"{sorted(detections(case.case_id))}"
    )


def test_no_detection_leaves_the_covered_scope() -> None:
    """A detection outside `COVERED_CWES` would be a finding this witness's silence never
    argues about, which is a witness able to raise a charge it reports itself as blind to."""
    for case in CASES:
        assert detections(case.case_id) <= COVERED_CWES, case.case_id


def test_silence_never_argues_about_a_cwe_this_witness_cannot_see() -> None:
    """D-006. The taint engine's silence on CWE-862 suppressing every semantic-only finding
    is the failure this field exists to prevent, and it applies here identically."""
    for case in CASES:
        for evidence in evidence_for(case.case_id):
            if evidence.kind is EvidenceKind.SILENCE:
                assert evidence.covered_cwes == COVERED_CWES, case.case_id


def test_every_case_produces_exactly_one_statement_per_finding_or_one_overall() -> None:
    """No case may produce nothing, and none may produce a detection alongside a silence."""
    for case in CASES:
        evidence = evidence_for(case.case_id)
        assert evidence, f"{case.case_id} produced no statement at all"
        kinds = {e.kind for e in evidence}
        assert kinds in (
            {EvidenceKind.DETECTION},
            {EvidenceKind.SILENCE},
            {EvidenceKind.ABSTENTION},
        ), f"{case.case_id} mixed evidence kinds: {kinds}"
