"""Turning claims into posteriors — through the production arithmetic, never beside it.

`posterior_from_cells` lives in `fusion.bayes` and is what `compute_bayesian_fusion` uses to
produce the number a developer is shown. This module calls that same function. A sweep that
computed its own odds product would be selecting a threshold for a quantity the engine does
not emit, and the two would agree right up until one of them changed.
"""

from __future__ import annotations

from collections.abc import Sequence

from codesheriff_engine.calibration.observations import Claim
from codesheriff_engine.calibration.prior import Prior, importance_weights
from codesheriff_engine.fusion.bayes import posterior_from_cells
from codesheriff_engine.fusion.ratios import WitnessRatios


def posteriors_for(
    claims: Sequence[Claim],
    table: dict[str, WitnessRatios],
    prior: Prior,
) -> list[float]:
    """One posterior per claim, at the declared base rate."""
    return [posterior_from_cells(claim.cells, table, prior.base_rate) for claim in claims]


def weights_for(claims: Sequence[Claim], prior: Prior) -> list[float]:
    """Per-claim importance weights that carry a balanced split to the base rate.

    The split's own prevalence is measured from the claims themselves rather than assumed to
    be 0.5. Spurious claims — a witness reporting a CWE the case is not about — are labelled
    safe and shift it, and a weight derived from an assumed 50/50 would then be reweighting
    from a population that is not the one in hand.
    """
    if not claims:
        return []
    prevalence = sum(claim.label for claim in claims) / len(claims)
    positive, negative = importance_weights(prior, prevalence)
    return [positive if claim.label else negative for claim in claims]
