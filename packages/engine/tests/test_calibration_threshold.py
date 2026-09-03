"""Selecting the alert threshold: the sweep, the objective, and the tie-break.

The threshold is the one number a developer feels directly — it decides whether a comment
says "alert" or stays quiet — and §6 gives it a split of its own so it is chosen after the
ratios are frozen. What is asserted here is that the selection is a procedure rather than a
preference: given the same posteriors it picks the same cut point, and it picks it for stated
reasons.
"""

from __future__ import annotations

import pytest

from codesheriff_engine.calibration.threshold import MIN_THRESHOLD, select, sweep


def test_the_sweep_covers_every_distinct_classifier() -> None:
    """One point per observed posterior, plus the floor. Thresholds between two adjacent
    posteriors behave identically, so anything more is duplicate rows in the artifact."""
    points = sweep([0.2, 0.6, 0.9], [True, False, True])
    assert [p.threshold for p in points] == [MIN_THRESHOLD, 0.2, 0.6, 0.9]


def test_recall_falls_and_precision_rises_as_the_threshold_climbs() -> None:
    """The trade-off the sweep exists to make visible, on a separable set."""
    posteriors = [0.9, 0.8, 0.4, 0.1]
    labels = [True, True, False, False]

    points = {p.threshold: p for p in sweep(posteriors, labels)}
    assert points[MIN_THRESHOLD].recall == pytest.approx(1.0)
    assert points[MIN_THRESHOLD].precision == pytest.approx(0.5)
    assert points[0.8].recall == pytest.approx(1.0)
    assert points[0.8].precision == pytest.approx(1.0)
    assert points[0.9].recall == pytest.approx(0.5)


def test_a_separable_set_selects_the_cut_that_alerts_on_exactly_the_true_claims() -> None:
    selection = select([0.9, 0.8, 0.4, 0.1], [True, True, False, False])
    assert selection.value == 0.8
    assert selection.objective == "max_f1"
    assert selection.at(0.8) is not None
    assert selection.at(0.8).f1 == pytest.approx(1.0)  # type: ignore[union-attr]


def test_ties_break_toward_the_higher_threshold() -> None:
    """Two cut points scoring identically are not really tied.

    Both of these alert on exactly the one true claim, so F1 is 1.0 at each. The higher one
    alerts on strictly fewer things as soon as the data moves, and the cost of an alert a
    developer learns to ignore is the whole argument for the project.
    """
    selection = select([0.9, 0.85, 0.1], [True, False, False])
    assert selection.value == 0.9


def test_weighting_to_a_low_base_rate_pushes_the_threshold_up() -> None:
    """Why nothing here is selected on unweighted rates.

    Unweighted, a middling cut looks precise because half the claims really are vulnerable.
    Weighted to a 3% base rate every false positive stands for thirty times as many real
    changes, and the selected threshold rises to pay for that.
    """
    posteriors = [0.9, 0.7, 0.65, 0.6, 0.2]
    labels = [True, True, False, False, False]

    unweighted = select(posteriors, labels)
    # Positives are rare in production: weight the two true claims down and the three false
    # ones up, exactly as `scoring.weights_for` does from the declared base rate.
    weights = [0.06, 0.06, 1.94, 1.94, 1.94]
    weighted = select(posteriors, labels, weights, base_rate=0.03)

    assert weighted.value >= unweighted.value
    assert weighted.weighted is True
    assert weighted.base_rate == 0.03


def test_selecting_from_nothing_raises() -> None:
    """A threshold chosen from an empty sweep is a hand-set constant with a procedure
    attached, which is the practice this chapter exists to remove."""
    with pytest.raises(ValueError, match="no validation posteriors"):
        select([], [])


def test_the_whole_sweep_is_recorded_not_just_the_winner() -> None:
    """So the sensitivity of the choice to the objective is an inspection, not a re-run."""
    selection = select([0.9, 0.5, 0.2], [True, False, False])
    assert len(selection.sweep) == 4
    assert selection.note.startswith("max weighted F1")
