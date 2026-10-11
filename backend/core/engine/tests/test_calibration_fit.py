"""The fitting arithmetic, checked against hand-computed numbers.

These are the numbers every posterior in the system is built from, so the test does not assert
"about right" — it asserts the exact smoothed ratio, computed by hand in the docstring of each
case. A fitting routine that is subtly wrong produces plausible ratios and a system that is
confidently miscalibrated, which is the failure mode this project exists to name.
"""

from __future__ import annotations

import pytest

from codesheriff_engine.calibration.fit import (
    LAPLACE_ALPHA,
    SILENCE_CEILING,
    fit_ratios,
    fit_witness,
)
from codesheriff_engine.calibration.observations import Claim
from codesheriff_engine.fusion.cells import RatioCell
from codesheriff_engine.fusion.ratios import LR_MAX, LR_MIN
from codesheriff_engine.fusion.witnesses import CONTEXT, RUNTIME, SEMANTIC, STRUCTURAL, WITNESSES


def claim(
    label: bool,
    cells: dict[str, RatioCell | None],
    case_id: str = "case",
    is_primary: bool = True,
) -> Claim:
    return Claim(
        case_id=case_id,
        pair_id="pair",
        split="calibration",
        cwe="CWE-89",
        finding_key="k",
        label=label,
        is_primary=is_primary,
        cells={witness: cells.get(witness) for witness in WITNESSES},
    )


def only(witness: str, cell: RatioCell | None) -> dict[str, RatioCell | None]:
    return {witness: cell}


def test_a_cell_seen_only_on_vulnerable_cases_fits_above_one() -> None:
    """Ten vulnerable high detections, ten safe silences.

    P(high | vuln) = (10 + 1) / (10 + 4) = 11/14; P(high | safe) = (0 + 1) / (10 + 4) = 1/14.
    LR = 11. The smoothing is what keeps it 11 rather than infinity, and 11 is a claim a
    corpus of twenty observations can support.
    """
    claims = [claim(True, only(STRUCTURAL, RatioCell.DETECTION_HIGH)) for _ in range(10)]
    claims += [claim(False, only(STRUCTURAL, RatioCell.SILENCE)) for _ in range(10)]

    fitted = fit_witness(STRUCTURAL, claims)
    high = fitted.cells[RatioCell.DETECTION_HIGH]

    assert high.n_vulnerable == 10
    assert high.n_safe == 0
    assert high.raw_ratio == pytest.approx(11.0)
    assert high.ratio == pytest.approx(11.0)
    assert high.clamped == ""


def test_a_cell_nobody_ever_selected_fits_to_exactly_one() -> None:
    """Pure smoothing prior, both sides, so the ratio is 1.0 — evidence of nothing.

    That is the right answer for a cell with no observations, and it is *arrived at* rather
    than asserted. The old `FALLBACK_RATIOS` asserted something similar by hand for a whole
    witness; this is the same conservatism with a derivation behind it.
    """
    claims = [claim(True, only(SEMANTIC, RatioCell.DETECTION_HIGH)) for _ in range(4)]
    claims += [claim(False, only(SEMANTIC, RatioCell.SILENCE)) for _ in range(4)]

    fitted = fit_witness(SEMANTIC, claims)
    assert fitted.cells[RatioCell.DETECTION_LOW].ratio == pytest.approx(1.0)


def test_abstentions_are_excluded_from_both_denominators() -> None:
    """An abstention is 1.0 by definition, and must not shift another cell's probability.

    The same ten-and-ten population as the first test, plus forty claims this witness said
    nothing about. If abstentions entered the denominators, every ratio would move; they do
    not, so the fitted number is identical and only `n_abstained` changes.
    """
    spoke = [claim(True, only(RUNTIME, RatioCell.DETECTION_HIGH)) for _ in range(10)]
    spoke += [claim(False, only(RUNTIME, RatioCell.SILENCE)) for _ in range(10)]
    silent = [claim(bool(i % 2), only(RUNTIME, None)) for i in range(40)]

    with_abstentions = fit_witness(RUNTIME, spoke + silent)
    without = fit_witness(RUNTIME, spoke)

    assert with_abstentions.n_abstained == 40
    assert without.n_abstained == 0
    for cell in RatioCell:
        assert with_abstentions.cells[cell].ratio == pytest.approx(without.cells[cell].ratio)


def test_a_silence_that_fits_above_one_is_clamped_and_says_so() -> None:
    """A weak witness can be silent on vulnerable code more often than on safe code.

    That is a fact about the witness, and the raw value is recorded. What it may not do is
    become a ratio above 1.0, which would make "looked and found nothing" evidence *for* a
    vulnerability (D-081). The clamp is visible, not silent.
    """
    claims = [claim(True, only(CONTEXT, RatioCell.SILENCE)) for _ in range(10)]
    claims += [claim(False, only(CONTEXT, RatioCell.DETECTION_LOW)) for _ in range(10)]

    fitted = fit_witness(CONTEXT, claims)
    silence = fitted.cells[RatioCell.SILENCE]

    assert silence.raw_ratio > 1.0
    assert silence.ratio == SILENCE_CEILING
    assert silence.clamped == "silence_ceiling"
    # And the clamped value still satisfies the contract's own constraint.
    assert fitted.ratios().silence < 1.0


def test_an_extreme_cell_is_clamped_to_the_bounds() -> None:
    """No witness earns a ratio of 40 from a corpus this size (`LR_MAX`)."""
    claims = [claim(True, only(STRUCTURAL, RatioCell.DETECTION_HIGH)) for _ in range(200)]
    claims += [claim(False, only(STRUCTURAL, RatioCell.SILENCE)) for _ in range(200)]

    fitted = fit_witness(STRUCTURAL, claims)
    high = fitted.cells[RatioCell.DETECTION_HIGH]

    assert high.raw_ratio > LR_MAX
    assert high.ratio == LR_MAX
    assert high.clamped == "lr_max"
    assert LR_MIN <= fitted.cells[RatioCell.SILENCE].ratio <= LR_MAX


def test_every_witness_is_fitted_even_one_that_never_spoke() -> None:
    """Four rows, always four — the roster is fixed and a fit covers all of it (D-082).

    A witness that abstained throughout gets four ratios of 1.0, which is the correct value
    for a witness nothing is known about and the reason no fallback table is needed.
    """
    claims = [claim(True, only(STRUCTURAL, RatioCell.DETECTION_HIGH))]
    claims += [claim(False, only(STRUCTURAL, RatioCell.SILENCE))]

    fit = fit_ratios(claims)

    assert set(fit.witnesses) == set(WITNESSES)
    never_spoke = fit.witnesses[RUNTIME]
    assert never_spoke.n_vulnerable_claims == 0
    assert never_spoke.n_safe_claims == 0
    for cell in (
        RatioCell.DETECTION_HIGH,
        RatioCell.DETECTION_MEDIUM,
        RatioCell.DETECTION_LOW,
    ):
        assert never_spoke.cells[cell].ratio == pytest.approx(1.0)

    # Silence is the one cell the type will not let sit at 1.0, so pure prior lands on the
    # ceiling instead — 0.999, which moves a posterior by a tenth of a percent. The witness
    # said nothing and is worth nothing either way; what matters is that it is a fitted value
    # with counts behind it rather than a hand-set fallback.
    silence = never_spoke.cells[RatioCell.SILENCE]
    assert silence.raw_ratio == pytest.approx(1.0)
    assert silence.ratio == SILENCE_CEILING


def test_fitting_nothing_raises_rather_than_returning_a_table_of_ones() -> None:
    """An empty fit is four tables of pure smoothing prior presented as a measurement."""
    with pytest.raises(ValueError, match="no claims"):
        fit_ratios([])


def test_the_recorded_probabilities_reproduce_the_ratio() -> None:
    """Every fitted number carries its own derivation, and it has to be the real one.

    A `CellFit` whose counts did not multiply back out to its ratio would make the artifact's
    apparent transparency worse than no transparency at all.
    """
    claims = [claim(True, only(SEMANTIC, RatioCell.DETECTION_MEDIUM)) for _ in range(7)]
    claims += [claim(True, only(SEMANTIC, RatioCell.SILENCE)) for _ in range(3)]
    claims += [claim(False, only(SEMANTIC, RatioCell.DETECTION_MEDIUM)) for _ in range(2)]
    claims += [claim(False, only(SEMANTIC, RatioCell.SILENCE)) for _ in range(8)]

    fitted = fit_witness(SEMANTIC, claims)
    for cell, cell_fit in fitted.cells.items():
        expected_pos = (cell_fit.n_vulnerable + LAPLACE_ALPHA) / (
            fitted.n_vulnerable_claims + LAPLACE_ALPHA * len(RatioCell)
        )
        expected_neg = (cell_fit.n_safe + LAPLACE_ALPHA) / (
            fitted.n_safe_claims + LAPLACE_ALPHA * len(RatioCell)
        )
        assert cell_fit.p_given_vulnerable == pytest.approx(expected_pos), cell
        assert cell_fit.p_given_safe == pytest.approx(expected_neg), cell
        assert cell_fit.raw_ratio == pytest.approx(expected_pos / expected_neg), cell
