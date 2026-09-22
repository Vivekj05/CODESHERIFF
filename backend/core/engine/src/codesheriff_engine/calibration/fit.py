"""Fitting one likelihood ratio per witness per cell, from labelled claims.

The quantity being fitted is a **class-conditional likelihood ratio**:

    LR(cell) = P(witness said `cell` | vulnerable) / P(witness said `cell` | safe)

Both halves are conditioned on the witness having said anything at all. A witness that could
not run has an LR of exactly 1.0 by definition, so abstentions are excluded from both
denominators rather than smoothed into them — including them would make the ratio depend on
how often a witness happened to be unavailable, which is a fact about the machine and not
about the code.

**This is why a balanced corpus is legitimate.** Both terms are conditioned on the label, so
neither depends on how common vulnerabilities are. Prevalence enters exactly once, through the
prior, and `prior.py` is where it is stated and rescaled. A fit that estimated `P(vulnerable |
cell)` directly would bake the corpus's 50% into every posterior and there would be no honest
way to take it back out.

**Laplace smoothing, alpha = 1, over the four cells.** With 46 calibration cases and four cells
per witness, a cell with no observations is ordinary rather than exceptional, and an unsmoothed
zero would produce an LR of 0 or infinity — a single witness able to drive any posterior to a
certainty. The counts are recorded beside every fitted number so a ratio that is mostly prior
can be seen to be one.
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, ConfigDict, Field

from codesheriff_engine.calibration.observations import Claim
from codesheriff_engine.fusion.cells import RatioCell
from codesheriff_engine.fusion.ratios import LR_MAX, LR_MIN, WitnessRatios
from codesheriff_engine.fusion.witnesses import WITNESSES

logger = logging.getLogger(__name__)

LAPLACE_ALPHA = 1.0
"""One pseudo-observation per cell per class. Recorded in the artifact, not assumed."""

SILENCE_CEILING = 0.999
"""The largest value a fitted `silence` may take.

`WitnessRatios.silence` is typed `lt=1.0`, and that constraint is load-bearing rather than
cosmetic: a silence at or above 1.0 would make a witness looking and finding nothing into
evidence *for* a vulnerability, which is not a claim any silence supports. A witness can
nonetheless fit above 1.0 — it happens when a witness stays silent on vulnerable cases more
often than on safe ones, which says the witness is weak, not that its silence is incriminating.

The fitted value is clamped here and the raw one is recorded in `CellFit.raw_ratio`, so the
constraint is visible in the artifact instead of being silently absorbed (D-081).
"""


class CellFit(BaseModel):
    """One cell's fitted ratio, with every number that produced it.

    A likelihood ratio nobody can recompute is an assertion with a decimal point. These are
    the inputs: two counts, two totals, the smoothing constant, and what the clamps did.
    """

    model_config = ConfigDict(frozen=True)

    cell: RatioCell
    n_vulnerable: int
    n_safe: int
    p_given_vulnerable: float
    p_given_safe: float
    raw_ratio: float
    """Before clamping. Equal to `ratio` unless a clamp bound bit.

    For a cell with no observations at all this is exactly 1.0 by definition (D-087); the
    smoothed value the counts would otherwise imply is in `smoothed_ratio`."""

    smoothed_ratio: float = 1.0
    """What Laplace smoothing alone produced, kept even where it was not used.

    Only differs from `raw_ratio` for an unobserved cell, and it is recorded so that the
    difference between "no evidence" and "an artefact of the class sizes" can be seen rather
    than taken on trust."""

    ratio: float
    clamped: str = ""
    """Which bound applied, if any: `lr_min`, `lr_max` or `silence_ceiling`."""


class WitnessFit(BaseModel):
    """Everything fitted for one witness, and the population it was fitted from."""

    model_config = ConfigDict(frozen=True)

    witness: str
    n_vulnerable_claims: int
    """Claims labelled vulnerable in which this witness said *something*."""

    n_safe_claims: int
    n_abstained: int
    """Claims where this witness contributed no cell. Excluded from both denominators."""

    cells: dict[RatioCell, CellFit]

    def ratios(self) -> WitnessRatios:
        return WitnessRatios(
            detection_high=self.cells[RatioCell.DETECTION_HIGH].ratio,
            detection_medium=self.cells[RatioCell.DETECTION_MEDIUM].ratio,
            detection_low=self.cells[RatioCell.DETECTION_LOW].ratio,
            silence=self.cells[RatioCell.SILENCE].ratio,
        )


class Fit(BaseModel):
    """The fitted table, plus how it was fitted."""

    model_config = ConfigDict(frozen=True)

    method: str = "laplace"
    alpha: float = LAPLACE_ALPHA
    lr_min: float = LR_MIN
    lr_max: float = LR_MAX
    silence_ceiling: float = SILENCE_CEILING
    witnesses: dict[str, WitnessFit] = Field(default_factory=dict)

    def table(self) -> dict[str, WitnessRatios]:
        """The `{witness: WitnessRatios}` mapping fusion multiplies with."""
        return {witness: fit.ratios() for witness, fit in self.witnesses.items()}


def _clamp(cell: RatioCell, raw: float) -> tuple[float, str]:
    if cell is RatioCell.SILENCE and raw > SILENCE_CEILING:
        return SILENCE_CEILING, "silence_ceiling"
    if raw < LR_MIN:
        return LR_MIN, "lr_min"
    if raw > LR_MAX:
        return LR_MAX, "lr_max"
    return raw, ""


def fit_witness(witness: str, claims: list[Claim]) -> WitnessFit:
    """One witness's four ratios, from every claim it made a statement about."""
    spoke = [claim for claim in claims if claim.cell(witness) is not None]
    abstained = len(claims) - len(spoke)

    positive = [claim for claim in spoke if claim.label]
    negative = [claim for claim in spoke if not claim.label]

    cells = list(RatioCell)
    denominator_pos = len(positive) + LAPLACE_ALPHA * len(cells)
    denominator_neg = len(negative) + LAPLACE_ALPHA * len(cells)

    fitted: dict[RatioCell, CellFit] = {}
    for cell in cells:
        n_pos = sum(1 for claim in positive if claim.cell(witness) is cell)
        n_neg = sum(1 for claim in negative if claim.cell(witness) is cell)
        p_pos = (n_pos + LAPLACE_ALPHA) / denominator_pos
        p_neg = (n_neg + LAPLACE_ALPHA) / denominator_neg
        smoothed = p_pos / p_neg

        # A cell nobody ever selected carries no information, and smoothing alone does not
        # say so. With both counts at zero the ratio reduces to the class sizes of the
        # witness's *other* cells — `runtime.sfi` spoke on 9 vulnerable claims and 5 safe
        # ones, so its two empty detection tiers came out at 0.69 and would have argued
        # mildly for safety on a tier that has never been observed. That is the abstention
        # principle in another costume: no observation is no evidence, and no evidence is
        # exactly 1.0 (D-087). The smoothed value is still recorded, as `smoothed_ratio`, so
        # the artefact is visible rather than corrected away.
        raw = 1.0 if (n_pos == 0 and n_neg == 0) else smoothed
        ratio, clamped = _clamp(cell, raw)
        if clamped == "silence_ceiling":
            logger.warning(
                "Witness %r fitted a silence ratio of %.3f, at or above 1.0: it stayed silent "
                "on vulnerable claims at least as often as on safe ones. Clamped to %.3f; the "
                "raw value is recorded. This says the witness is weak, not that its silence is "
                "incriminating.",
                witness,
                raw,
                SILENCE_CEILING,
            )
        fitted[cell] = CellFit(
            cell=cell,
            n_vulnerable=n_pos,
            n_safe=n_neg,
            p_given_vulnerable=p_pos,
            p_given_safe=p_neg,
            raw_ratio=raw,
            smoothed_ratio=smoothed,
            ratio=ratio,
            clamped=clamped,
        )

    return WitnessFit(
        witness=witness,
        n_vulnerable_claims=len(positive),
        n_safe_claims=len(negative),
        n_abstained=abstained,
        cells=fitted,
    )


def fit_ratios(claims: list[Claim]) -> Fit:
    """Fit every registered witness, whether or not it ever spoke.

    A witness that abstained on the whole split still gets a row — four ratios, each of them
    the smoothing prior alone, which is 1.0. That is the correct value for a witness nothing
    is known about, and it is arrived at by fitting rather than by a fallback constant. There
    is no `FALLBACK_RATIOS` any more for the same reason: the roster is fixed, so a witness
    with no row means the artifact is incomplete, not that a timid default should be invented
    (D-082).
    """
    if not claims:
        raise ValueError(
            "no claims to fit on. A fit from an empty observation set would be four tables of "
            "pure smoothing prior presented as a measurement."
        )
    return Fit(witnesses={witness: fit_witness(witness, claims) for witness in WITNESSES})
