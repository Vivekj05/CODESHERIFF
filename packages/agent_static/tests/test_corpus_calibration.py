"""`structural.taint` measured against ground truth — on the calibration split, and only that.

**This file must never read the validation or the test split.** §6 reserves validation for
threshold selection and permits the test split to be evaluated exactly once, at the end. Iterating
rules while watching either one is fitting on it, whatever it is called, and a test that runs on
every commit is the most thorough form of iterating. `test_only_the_calibration_split_is_read`
asserts the restriction rather than trusting it.

The import is deliberate and does not breach D-047. The contract that forbids reading the corpus
names the `static_agent` **package** — an agent that can read `label` is being told the answer, and
one that can read `detectable_by` can be excused by the field that exists to excuse it fairly. A
test is where the labels are supposed to be read; it is the only place the numbers below can come
from.

`detectable_by` is a floor, not a ceiling (D-047). It was authored from a pre-registered rule before
any agent ran and is never widened afterwards, so a detection it did not predict is a bonus rather
than a defect — but a *missed* prediction is a regression, and that is what these assertions catch.
"""

from __future__ import annotations

import pytest

from codesheriff_contracts import ChangeUnit, EvidenceKind
from codesheriff_corpus.loader import load_cases
from codesheriff_corpus.models import CorpusCase, Label
from codesheriff_corpus.splits import Split, split_for
from static_agent.config import StaticConfig
from static_agent.taint.engine import analyze_taint

AGENT_ID = "structural.taint"
CONFIG = StaticConfig()


def unit_of(case: CorpusCase) -> ChangeUnit:
    """A corpus case as the object an agent actually receives.

    The same shape `codesheriff_engine.extraction` produces from a pull request, which is the whole
    basis for applying a ratio fitted on one to the other (D-048).
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


def calibration_cases() -> list[CorpusCase]:
    return [case for case in load_cases() if split_for(case) is Split.CALIBRATION]


def detected_cwes(case: CorpusCase) -> set[str]:
    evidence = analyze_taint(unit_of(case), CONFIG)
    return {e.cwe for e in evidence if e.kind is EvidenceKind.DETECTION and e.cwe}


CASES = calibration_cases()
EXPECTED = [c for c in CASES if c.label is Label.VULNERABLE and AGENT_ID in c.detectable_by]
SAFE = [c for c in CASES if c.label is Label.SAFE]


def test_only_the_calibration_split_is_read() -> None:
    """The guard on this whole file. §6 is not enforceable by intention alone."""
    assert CASES, "the calibration split is empty — the corpus or the splits did not load"
    assert all(split_for(case) is Split.CALIBRATION for case in CASES)


@pytest.mark.parametrize("case", EXPECTED, ids=lambda c: c.case_id)
def test_every_predicted_case_is_detected(case: CorpusCase) -> None:
    """`detectable_by` was pre-registered before any agent ran. Missing one is a regression."""
    assert case.cwe in detected_cwes(case), (
        f"{case.case_id} is labelled detectable by {AGENT_ID} and was not detected. "
        f"Rationale: {case.rationale}"
    )


@pytest.mark.parametrize("case", SAFE, ids=lambda c: c.case_id)
def test_no_safe_case_is_reported(case: CorpusCase) -> None:
    """The twins are deliberately near, so each of these is a specific false-positive trap.

    The safe member of `cwe-089-order-sort` still builds its query with an f-string; the safe
    `cwe-918-link-preview` still calls `urlopen`. A rule keyed on the shape rather than the flaw
    fires on both members and is measured for it here.
    """
    assert case.cwe not in detected_cwes(case), (
        f"false positive on the safe twin {case.case_id}, which is safe because: {case.rationale}"
    )


def test_recall_and_precision_on_the_calibration_split() -> None:
    """The headline numbers, asserted so they cannot silently regress.

    These are *not* calibrated figures and nothing may present them as such — they are a
    development measurement on the split reserved for development. Chapter 14 fits likelihood
    ratios, and the validation and test splits stay sealed until then.

    The safe-twin count rose from 18 to 23 when Chapter 12 added eight cross-PR pairs, five of
    which landed in calibration. Recall is unchanged at 13: those pairs are CWE-862 and
    CWE-639, and no taint path can see a missing permission check — which is the heterogeneity
    claim `test_authorisation_cases_are_left_to_another_witness` pins. Five more safe twins
    this agent must stay quiet on is a strictly stronger false-positive measurement.
    """
    detected = sum(case.cwe in detected_cwes(case) for case in EXPECTED)
    false_positives = sum(case.cwe in detected_cwes(case) for case in SAFE)

    assert detected == len(EXPECTED) == 13
    assert false_positives == 0
    assert len(SAFE) == 23


def test_the_agent_never_raises_on_any_corpus_case() -> None:
    """Zero unhandled exceptions across a full run is a `CLAUDE.md` target, not an aspiration."""
    for case in CASES:
        evidence = analyze_taint(unit_of(case), CONFIG)
        assert evidence, f"{case.case_id} produced no statement at all"
        assert not any(
            e.kind is EvidenceKind.ABSTENTION and e.reason == "internal_error" for e in evidence
        ), f"{case.case_id} crashed the engine"


def test_authorisation_cases_are_left_to_another_witness() -> None:
    """Heterogeneity, asserted rather than assumed.

    The authz CWEs exist in the corpus to prove the four agents fail differently: no taint path
    can see a missing permission check. This agent must stay silent on them *and* must not claim
    coverage of them, or its silence would suppress the only witness that can see them (D-006).
    """
    authz = [c for c in CASES if c.cwe in ("CWE-862", "CWE-639") and c.label is Label.VULNERABLE]
    assert authz, "the calibration split should contain authorisation cases"

    for case in authz:
        evidence = analyze_taint(unit_of(case), CONFIG)
        assert case.cwe not in detected_cwes(case)
        for item in evidence:
            if item.kind is EvidenceKind.SILENCE:
                assert not item.covers(case.cwe)
