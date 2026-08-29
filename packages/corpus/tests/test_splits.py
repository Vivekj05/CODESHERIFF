"""The splits, and the property the chapter names explicitly: twins never separate.

PLAN.md Chapter 7: "a test fails if a twin pair is split across splits". Assignment is
by `pair_id`, so that is true by construction — and the test is here anyway, because
the construction is a choice someone could later change while these tests kept
passing for the wrong reason.
"""

from __future__ import annotations

import pytest

from codesheriff_corpus import Split, load_cases, load_pairs, load_splits, pairs_in
from codesheriff_corpus.loader import CorpusError
from codesheriff_corpus.splits import DEFAULT_RATIOS, SplitFile, assign


def test_splits_load_and_cover_the_corpus_exactly() -> None:
    """No pair unassigned, no assignment orphaned.

    Both failures are silent in the direction that matters: an unassigned pair simply
    never appears in a fit, and an orphaned assignment describes a case that no longer
    exists. `load_splits` raises on either.
    """
    splits = load_splits()
    assert set(splits.assignments) == set(load_pairs())


def test_every_case_lands_in_exactly_one_split() -> None:
    assignments = load_splits().assignments
    for case in load_cases():
        assert case.pair_id in assignments, case.case_id
    seen = [pair for split in Split for pair in pairs_in(split)]
    assert len(seen) == len(set(seen)) == len(assignments)


def test_twins_are_never_split() -> None:
    """The chapter's second acceptance criterion.

    A twin pair differs by a sanitizer call. With the vulnerable member in calibration
    and the safe one in test, a fitted ratio would have been tuned on all but a few
    characters of the case it is later scored against — the leak this test exists for.
    """
    assignments = load_splits().assignments
    for pair_id, (vulnerable, safe) in load_pairs().items():
        assert assignments[vulnerable.pair_id] is assignments[safe.pair_id], (
            f"{pair_id}: twins are in different splits"
        )


def test_split_sizes_match_the_recorded_ratios() -> None:
    """60/20/20 by pair (D-045)."""
    splits = load_splits()
    total = len(splits.assignments)
    for split, ratio in splits.ratios.items():
        assert len(pairs_in(split)) == round(total * ratio), split.value


def test_every_cwe_appears_in_the_calibration_split() -> None:
    """Where the ratios are fitted, no CWE may be missing.

    Validation and test cannot make the same guarantee: six pairs cannot cover ten
    CWEs. That limitation is real and recorded in DECISIONS.md D-045 rather than
    engineered away by reseeding until the draw looks better.
    """
    calibration = set(pairs_in(Split.CALIBRATION))
    covered = {v.cwe for pid, (v, _s) in load_pairs().items() if pid in calibration}
    assert covered == {c.cwe for c in load_cases()}


def test_assignment_is_reproducible_from_the_recorded_seed() -> None:
    """The seed is in splits.json so the draw can be re-derived and shown to be unrigged."""
    splits = load_splits()
    assert assign(seed=splits.seed, ratios=splits.ratios) == splits.assignments


def test_assignment_never_moves_a_pair_that_already_has_a_split() -> None:
    """The only real defence against a split quietly changing.

    A committed checksum verified by a test is the mechanism that was already defeated
    in this repository (AUDIT.md 4.8: the expected hash was rewritten to make the test
    pass), so it is not the mechanism used here. What is used: assignment refuses to
    move, and `split_hash` is recorded on every calibration run so a later edit makes
    that run visibly stale.
    """
    settled = load_splits().assignments
    reassigned = assign(seed=settled and 999, existing=dict(settled))
    assert reassigned == settled

    partial = {p: s for i, (p, s) in enumerate(sorted(settled.items())) if i < 5}
    grown = assign(seed=12345, existing=dict(partial))
    assert set(grown) == set(settled)
    for pair_id, split in partial.items():
        assert grown[pair_id] is split


def test_assignment_rejects_an_unknown_pair() -> None:
    with pytest.raises(CorpusError, match="no longer exist"):
        assign(seed=1, existing={"cwe-999-not-a-pair": Split.TEST})


def test_ratios_must_be_a_complete_distribution() -> None:
    with pytest.raises(ValueError, match="sum to"):
        SplitFile(
            generated="2026-08-29",
            seed=1,
            ratios={Split.CALIBRATION: 0.5, Split.VALIDATION: 0.2, Split.TEST: 0.2},
        )
    with pytest.raises(ValueError, match="every split"):
        SplitFile(generated="2026-08-29", seed=1, ratios={Split.CALIBRATION: 1.0})


def test_default_ratios_favour_calibration() -> None:
    """Twelve cells to fit against one scalar each for the other two splits."""
    assert DEFAULT_RATIOS[Split.CALIBRATION] > DEFAULT_RATIOS[Split.VALIDATION]
    assert sum(DEFAULT_RATIOS.values()) == pytest.approx(1.0)
