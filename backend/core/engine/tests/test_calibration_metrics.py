"""ECE and Brier — the mandatory acceptance criteria, checked against worked examples.

`CLAUDE.md` makes both non-optional, which means a bug in either would not be a bug in a
diagnostic: it would be a bug in the claim. Every assertion here is a number computed by hand
in the docstring, because a metric implementation validated only against itself is exactly as
trustworthy as the numbers it will later be used to defend.
"""

from __future__ import annotations

import pytest

from codesheriff_engine.calibration.metrics import (
    brier_score,
    evaluate,
    expected_calibration_error,
    reliability_bins,
)
from codesheriff_engine.calibration.prior import Prior, importance_weights


def test_a_perfectly_confident_and_correct_predictor_scores_zero() -> None:
    """Brier 0, ECE 0. The degenerate case, which every implementation must get right."""
    posteriors = [1.0, 1.0, 0.0, 0.0]
    labels = [True, True, False, False]

    assert brier_score(posteriors, labels) == pytest.approx(0.0)
    assert expected_calibration_error(posteriors, labels) == pytest.approx(0.0)


def test_a_confidently_wrong_predictor_scores_one() -> None:
    """Brier 1.0 and ECE 1.0: the worst attainable, and the shape of the tool this
    project criticises — certain, and certain in the wrong direction."""
    posteriors = [1.0, 0.0]
    labels = [False, True]

    assert brier_score(posteriors, labels) == pytest.approx(1.0)
    assert expected_calibration_error(posteriors, labels) == pytest.approx(1.0)


def test_a_well_calibrated_but_unconfident_predictor_has_low_ece_and_high_brier() -> None:
    """Ten claims at 0.5, five of them true.

    Brier = mean (0.5 - y)^2 = 0.25 — poor accuracy. ECE = |0.5 - 0.5| = 0 — perfect
    calibration. The two numbers disagree, and that disagreement is the whole reason both are
    reported: a system can be honest about being unsure, and that is not the same as being
    wrong.
    """
    posteriors = [0.5] * 10
    labels = [True] * 5 + [False] * 5

    assert brier_score(posteriors, labels) == pytest.approx(0.25)
    assert expected_calibration_error(posteriors, labels) == pytest.approx(0.0)


def test_ece_is_the_weighted_mean_gap_over_populated_bins() -> None:
    """Two bins, hand-computed.

    Four claims at 0.9 of which two are true -> bin [0.9, 1.0): confidence 0.9, frequency
    0.5, gap 0.4, weight 4. Four claims at 0.1 of which none are true -> bin [0.1, 0.2):
    confidence 0.1, frequency 0.0, gap 0.1, weight 4. ECE = (4*0.4 + 4*0.1) / 8 = 0.25.
    """
    posteriors = [0.9] * 4 + [0.1] * 4
    labels = [True, True, False, False, False, False, False, False]

    assert expected_calibration_error(posteriors, labels) == pytest.approx(0.25)


def test_empty_bins_contribute_nothing_rather_than_zero_error() -> None:
    """With fourteen validation claims most bins are empty.

    Averaging their absence in would report a calibration error that falls as the sample
    shrinks — the smaller the evidence, the better the number would look.
    """
    posteriors = [0.95, 0.95]
    labels = [True, False]

    bins = reliability_bins(posteriors, labels)
    assert len(bins) == 1
    # The gap is 0.45 in the one populated bin; if the nine empty bins counted as zero error
    # the ECE would be 0.045, which is a tenth of the truth.
    assert expected_calibration_error(posteriors, labels) == pytest.approx(0.45)


def test_a_posterior_of_exactly_one_lands_in_the_top_bin() -> None:
    """The top bin owns its right edge. Otherwise the most confident claim is dropped."""
    bins = reliability_bins([1.0], [True])
    assert len(bins) == 1
    assert bins[0].upper == 1.0
    assert bins[0].n == 1


def test_weighting_moves_a_balanced_measurement_toward_the_base_rate() -> None:
    """The reason nothing here is reported unweighted.

    A 50/50 split says a 50% posterior is perfectly calibrated. Re-weighted to a 3% base rate
    the same predictions are badly over-confident, and it is the second number that describes
    what a developer will experience.
    """
    posteriors = [0.5] * 10
    labels = [True] * 5 + [False] * 5

    prior = Prior(base_rate=0.03, corpus_prevalence=0.5)
    positive, negative = importance_weights(prior, 0.5)
    weights = [positive if label else negative for label in labels]

    unweighted = evaluate("validation", posteriors, labels)
    weighted = evaluate("validation", posteriors, labels, weights)

    assert unweighted.ece == pytest.approx(0.0)
    assert weighted.ece == pytest.approx(0.47)
    assert weighted.observed_rate == pytest.approx(0.03)
    assert weighted.weighted is True


def test_weights_must_match_the_claims_they_weight() -> None:
    with pytest.raises(ValueError, match="one weight per claim"):
        brier_score([0.5, 0.5], [True, False], [1.0])
