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
from codesheriff_corpus.splits import DEFAULT_RATIOS, SplitFile, _targets, assign


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
    """60/20/20 by pair (D-045), under the same allocation `assign` uses.

    Compared against `_targets`, the largest-remainder allocation, rather than against
    `round(total * ratio)` per split. Rounding each split independently does not sum to the
    total: at 38 pairs it asks for 23 + 8 + 8 = 39. It happened to agree while the corpus held
    30 pairs and 30 divides 60/20/20 exactly, so the arithmetic error was invisible until
    Chapter 12 added eight cross-PR pairs.
    """
    splits = load_splits()
    targets = _targets(len(splits.assignments), splits.ratios)
    for split in Split:
        assert len(pairs_in(split)) == targets[split], split.value


def test_every_cwe_appears_in_the_calibration_split() -> None:
    """Where the ratios are fitted, no CWE may be missing.

    Validation and test cannot make the same guarantee: six pairs cannot cover ten
    CWEs. That limitation is real and recorded in DECISIONS.md D-045 rather than
    engineered away by reseeding until the draw looks better.
    """
    calibration = set(pairs_in(Split.CALIBRATION))
    covered = {v.cwe for pid, (v, _s) in load_pairs().items() if pid in calibration}
    assert covered == {c.cwe for c in load_cases()}


def test_assignment_is_a_fixed_point_of_the_recorded_seed() -> None:
    """Re-running the recorded procedure over the recorded assignment changes nothing.

    This is the reproducibility claim an incrementally grown corpus can actually make, and it
    is weaker than the one this test made before Chapter 12. A from-scratch draw over 38 pairs
    does not reproduce the committed assignment, and must not: the original 30 were drawn when
    the corpus held 30, and D-045 ranks never moving a settled pair above matching a fresh
    draw. Re-deriving the whole thing therefore needs the order the pairs were added in, not
    the seed alone.

    What survives is checkable and is what the integrity claim rests on: the seed was fixed
    before the draw and has not been rerolled, no settled pair has moved
    (`test_assignment_never_moves_a_pair_that_already_has_a_split`), and running `assign`
    again is a no-op — so no pair sits anywhere the recorded procedure would not have put it.
    """
    splits = load_splits()
    assert assign(seed=splits.seed, ratios=splits.ratios, existing=dict(splits.assignments)) == (
        splits.assignments
    )


def test_a_from_scratch_draw_is_deliberately_not_reproduced() -> None:
    """The cost of immutability, asserted so it is a decision rather than a surprise.

    If this ever starts passing, the corpus has been re-drawn from scratch — which would mean
    settled pairs moved, including in and out of the sealed test split.
    """
    splits = load_splits()
    fresh = assign(seed=splits.seed, ratios=splits.ratios)
    assert fresh != splits.assignments


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
