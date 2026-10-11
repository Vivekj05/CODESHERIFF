"""Selecting the alert threshold on the validation split, and only there.

§6 is explicit: ratios are fitted on calibration, the threshold is selected on validation, and
the test split is evaluated exactly once at the end. The reason the threshold gets a split of
its own is that it is chosen *after* seeing what the fitted ratios produce — choosing it on
calibration would mean picking the cut point on the same data that decided where the
posteriors landed, and the resulting precision would be a description of the corpus.

**Rates are weighted to the declared base rate.** A threshold picked from unweighted precision
on a 50/50 split is picked for a world where half of all pull requests are vulnerable. Under
that assumption almost any threshold looks precise, and the one selected would be far too low
for production. `scoring.weights_for` is applied before anything here counts a positive.

**The objective is F1, ties broken toward the higher threshold.** F1 balances the two failure
modes this project cares about in opposite directions — a missed vulnerability and an alert a
developer learns to ignore — and it needs no second hand-set constant of the kind a precision
floor would introduce. Ties break upward because two thresholds with identical scores on
fourteen validation cases are not really tied: the higher one alerts on strictly fewer things,
and the cost of a false alert here is the whole argument for the project.

The full sweep is recorded in the artifact, so the sensitivity of the choice to the objective
is an inspection rather than a re-run.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict, Field

MIN_THRESHOLD = 0.01
"""Never select a threshold of 0.0, which alerts on everything a witness merely looked at."""


class SweepPoint(BaseModel):
    """Weighted confusion at one candidate threshold."""

    model_config = ConfigDict(frozen=True)

    threshold: float
    true_positives: float
    false_positives: float
    false_negatives: float
    precision: float
    recall: float
    f1: float
    n_alerts: int
    """Unweighted count, so the sweep can be read as "how many of these cases fire"."""


class ThresholdSelection(BaseModel):
    """The chosen threshold, the objective that chose it, and the whole sweep."""

    model_config = ConfigDict(frozen=True)

    value: float
    objective: str = "max_f1"
    selected_on: str = "validation"
    weighted: bool = True
    base_rate: float
    sweep: tuple[SweepPoint, ...] = Field(default_factory=tuple)
    note: str = ""

    def at(self, threshold: float) -> SweepPoint | None:
        return next((p for p in self.sweep if p.threshold == threshold), None)


def _candidates(posteriors: Sequence[float]) -> list[float]:
    """Every posterior is a candidate, plus a floor.

    Thresholds between two adjacent posteriors are behaviourally identical, so sweeping the
    observed values covers every distinct classifier. Using the posteriors themselves (with
    `>=` comparison) rather than midpoints keeps the selected number one a reader can find in
    the data.
    """
    return sorted({MIN_THRESHOLD, *(p for p in posteriors if p >= MIN_THRESHOLD)})


def sweep(
    posteriors: Sequence[float],
    labels: Sequence[bool],
    weights: Sequence[float] | None = None,
) -> list[SweepPoint]:
    resolved = list(weights) if weights is not None else [1.0] * len(labels)
    points: list[SweepPoint] = []
    for threshold in _candidates(posteriors):
        tp = fp = fn = 0.0
        alerts = 0
        for posterior, label, weight in zip(posteriors, labels, resolved, strict=True):
            alerted = posterior >= threshold
            alerts += int(alerted)
            if alerted and label:
                tp += weight
            elif alerted:
                fp += weight
            elif label:
                fn += weight
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        points.append(
            SweepPoint(
                threshold=threshold,
                true_positives=tp,
                false_positives=fp,
                false_negatives=fn,
                precision=precision,
                recall=recall,
                f1=f1,
                n_alerts=alerts,
            )
        )
    return points


def select(
    posteriors: Sequence[float],
    labels: Sequence[bool],
    weights: Sequence[float] | None = None,
    base_rate: float = 0.0,
    split: str = "validation",
) -> ThresholdSelection:
    """Maximise weighted F1; where several thresholds tie, take the highest."""
    if not posteriors:
        raise ValueError(
            "no validation posteriors to sweep. A threshold selected from nothing is a "
            "hand-set constant with a procedure attached."
        )
    points = sweep(posteriors, labels, weights)
    best = max(points, key=lambda p: (p.f1, p.threshold))
    return ThresholdSelection(
        value=best.threshold,
        selected_on=split,
        weighted=weights is not None,
        base_rate=base_rate,
        sweep=tuple(points),
        note=(
            f"max weighted F1 = {best.f1:.3f} at p >= {best.threshold:.4f} "
            f"(precision {best.precision:.3f}, recall {best.recall:.3f}, "
            f"{best.n_alerts} of {len(posteriors)} claims alerting)"
        ),
    )
