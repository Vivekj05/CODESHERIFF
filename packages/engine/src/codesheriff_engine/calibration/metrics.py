"""Calibration metrics: the acceptance criteria, not an appendix.

CLAUDE.md makes ECE and Brier **mandatory acceptance criteria**. The thesis is that a stated
87% corresponds to being right about 87% of the time, and these two numbers are what that
sentence means quantitatively:

* **Brier** is the mean squared error of the probabilities. It rewards being both right and
  confident, and it is the score a detector optimises when it is trying to be *accurate*.
* **ECE** is the gap between confidence and accuracy, averaged over bins. It is the one that
  speaks to the claim: a model can have an excellent Brier score and still say 90% when it
  means 60%, and that model is precisely the one this project exists to criticise.

Both are computed **weighted** (`prior.importance_weights`). Measured raw on a balanced split
they describe a population that does not exist — one where half of all pull requests introduce
a vulnerability — and the number that reaches the paper has to be about production.

Bins are equal-width over [0, 1], which is the standard ECE and the one a reader will assume.
Empty bins contribute nothing rather than contributing zero error: with 14 validation cases
most bins are empty, and averaging their absence in would report a calibration error that
falls as the sample shrinks.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

DEFAULT_BINS = 10


class ReliabilityBin(BaseModel):
    """One row of the reliability diagram the dashboard and the paper both render."""

    model_config = ConfigDict(frozen=True)

    lower: float
    upper: float
    n: int
    weight: float
    mean_confidence: float
    observed_frequency: float

    @property
    def gap(self) -> float:
        return abs(self.mean_confidence - self.observed_frequency)


class CalibrationMetrics(BaseModel):
    """ECE, Brier and the bins they came from, for one split."""

    model_config = ConfigDict(frozen=True)

    split: str
    n_claims: int
    weighted: bool
    ece: float
    brier: float
    mean_posterior: float
    observed_rate: float
    bins: tuple[ReliabilityBin, ...] = ()
    note: str = ""


def _weights(labels: Sequence[bool], weights: Sequence[float] | None) -> list[float]:
    if weights is None:
        return [1.0] * len(labels)
    if len(weights) != len(labels):
        raise ValueError("one weight per claim, or none at all")
    return list(weights)


def brier_score(
    posteriors: Sequence[float],
    labels: Sequence[bool],
    weights: Sequence[float] | None = None,
) -> float:
    resolved = _weights(labels, weights)
    total = sum(resolved)
    if total <= 0.0:
        return 0.0
    return (
        sum(w * (p - float(y)) ** 2 for p, y, w in zip(posteriors, labels, resolved, strict=True))
        / total
    )


def reliability_bins(
    posteriors: Sequence[float],
    labels: Sequence[bool],
    weights: Sequence[float] | None = None,
    bins: int = DEFAULT_BINS,
) -> list[ReliabilityBin]:
    resolved = _weights(labels, weights)
    edges = [i / bins for i in range(bins + 1)]
    out: list[ReliabilityBin] = []
    for index in range(bins):
        lower, upper = edges[index], edges[index + 1]
        # The top bin owns its right edge, so a posterior of exactly 1.0 is not dropped.
        members = [
            (p, y, w)
            for p, y, w in zip(posteriors, labels, resolved, strict=True)
            if (lower <= p < upper) or (index == bins - 1 and p == upper)
        ]
        if not members:
            continue
        mass = sum(w for _p, _y, w in members)
        out.append(
            ReliabilityBin(
                lower=lower,
                upper=upper,
                n=len(members),
                weight=mass,
                mean_confidence=sum(w * p for p, _y, w in members) / mass,
                observed_frequency=sum(w * float(y) for _p, y, w in members) / mass,
            )
        )
    return out


def expected_calibration_error(
    posteriors: Sequence[float],
    labels: Sequence[bool],
    weights: Sequence[float] | None = None,
    bins: int = DEFAULT_BINS,
) -> float:
    """Weighted mean absolute gap between stated confidence and observed frequency."""
    populated = reliability_bins(posteriors, labels, weights, bins)
    mass = sum(b.weight for b in populated)
    if mass <= 0.0:
        return 0.0
    return sum(b.weight * b.gap for b in populated) / mass


def evaluate(
    split: str,
    posteriors: Sequence[float],
    labels: Sequence[bool],
    weights: Sequence[float] | None = None,
    bins: int = DEFAULT_BINS,
    note: str = "",
) -> CalibrationMetrics:
    resolved = _weights(labels, weights)
    mass = sum(resolved) or 1.0
    return CalibrationMetrics(
        split=split,
        n_claims=len(posteriors),
        weighted=weights is not None,
        ece=expected_calibration_error(posteriors, labels, weights, bins),
        brier=brier_score(posteriors, labels, weights),
        mean_posterior=sum(w * p for p, w in zip(posteriors, resolved, strict=True)) / mass,
        observed_rate=sum(w * float(y) for y, w in zip(labels, resolved, strict=True)) / mass,
        bins=tuple(reliability_bins(posteriors, labels, weights, bins)),
        note=note,
    )
