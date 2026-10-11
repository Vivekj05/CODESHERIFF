"""Calibration, then validation, then stop. The order is §6 and it is not a style choice.

    1. Fit the likelihood ratios on the **calibration** split.
    2. Freeze them, and select the alert threshold on the **validation** split.
    3. Leave the **test** split alone until Chapter 18, where it is evaluated once.

Each step sees only what it is entitled to see, and the code is arranged so that violating the
order takes deliberate effort: `fit_from_observations` takes two `ObservationSet`s and refuses
either one that is not the split it claims to be, and the runner cannot produce a test-split
set at all.

The artifact this writes replaces `fusion/ratios.py`'s hand-set constants entirely. After it
lands there is no default prior, no default threshold and no default ratio table anywhere in
the codebase — which is the Chapter 14 acceptance criterion, and the reason this file deletes
rather than supplements.
"""

from __future__ import annotations

import logging
from pathlib import Path

from codesheriff_corpus.models import Split
from codesheriff_engine.calibration import artifact as artifact_module
from codesheriff_engine.calibration.artifact import CalibrationArtifact
from codesheriff_engine.calibration.fit import fit_ratios
from codesheriff_engine.calibration.metrics import evaluate
from codesheriff_engine.calibration.observations import ObservationSet
from codesheriff_engine.calibration.prior import DEFAULT_BASE_RATE, Prior
from codesheriff_engine.calibration.scoring import posteriors_for, weights_for
from codesheriff_engine.calibration.threshold import select

logger = logging.getLogger(__name__)

PRIOR_RATIONALE = (
    "Declared, not measured. The corpus is twin-paired, so its prevalence is 0.5 by "
    "construction — a fact about how the cases were written, not about how often a changed "
    "function is vulnerable. The likelihood ratios are conditioned on the label and so do not "
    "depend on prevalence at all; the base rate enters exactly here, and changing it re-scales "
    "every posterior by a recorded factor without re-fitting a single ratio."
)


def _require(observations: ObservationSet, split: Split) -> ObservationSet:
    if observations.split != split.value:
        raise ValueError(
            f"expected the {split.value} split and got {observations.split}. Ratios are fitted "
            f"on calibration and the threshold is selected on validation (§6); crossing them "
            f"means the cut point was chosen on the data that decided where the posteriors fell."
        )
    return observations


def fit_from_observations(
    calibration: ObservationSet,
    validation: ObservationSet,
    *,
    base_rate: float = DEFAULT_BASE_RATE,
    notes: str = "",
) -> CalibrationArtifact:
    """The whole fit, in the order §6 prescribes."""
    _require(calibration, Split.CALIBRATION)
    _require(validation, Split.VALIDATION)

    if calibration.corpus_hash != validation.corpus_hash:
        raise ValueError(
            "the two observation sets were recorded against different corpora. One artifact "
            "records one corpus hash, and it has to be true of both halves of the fit."
        )

    fit = fit_ratios(list(calibration.claims))
    table = fit.table()

    prior = Prior(
        base_rate=base_rate,
        source="declared",
        corpus_prevalence=calibration.prevalence(),
        rationale=PRIOR_RATIONALE,
    )

    validation_claims = list(validation.claims)
    validation_posteriors = posteriors_for(validation_claims, table, prior)
    validation_labels = [claim.label for claim in validation_claims]
    validation_weights = weights_for(validation_claims, prior)

    threshold = select(
        validation_posteriors,
        validation_labels,
        validation_weights,
        base_rate=prior.base_rate,
        split=Split.VALIDATION.value,
    )

    calibration_claims = list(calibration.claims)
    calibration_posteriors = posteriors_for(calibration_claims, table, prior)

    metrics = {
        "validation": evaluate(
            Split.VALIDATION.value,
            validation_posteriors,
            validation_labels,
            validation_weights,
            note=(
                "Weighted to the declared base rate, so these estimate production rather than "
                "the balanced corpus. Selection-time figures: the threshold was chosen on this "
                "split, so they are not an unbiased estimate of held-out performance. That "
                "number is the test split's, and Chapter 18 takes it once."
            ),
        ),
        "calibration": evaluate(
            Split.CALIBRATION.value,
            calibration_posteriors,
            [claim.label for claim in calibration_claims],
            weights_for(calibration_claims, prior),
            note=(
                "In-sample. The ratios were fitted on these claims, so this is a description of "
                "the fit and not a measurement of it — recorded because a fit that cannot even "
                "calibrate its own training split is broken, and that is worth being able to see."
            ),
        ),
    }

    return artifact_module.build(
        corpus_hash=calibration.corpus_hash,
        split_hash=calibration.split_hash,
        fit=fit,
        prior=prior,
        threshold=threshold,
        metrics=metrics,
        provenance={
            "calibration": calibration.provenance,
            "validation": validation.provenance,
        },
        notes=notes,
    )


def write_artifact(artifact: CalibrationArtifact, path: Path | None = None) -> Path:
    target = path or artifact_module.PACKAGED_ARTIFACT
    artifact.save(target)
    logger.info("wrote %s — %s", target, artifact.summary())
    return target
