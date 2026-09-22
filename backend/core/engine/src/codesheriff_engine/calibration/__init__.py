"""Fitting the numbers fusion multiplies with (PLAN.md Chapter 14).

Everything here is arithmetic over labelled claims. **No agent is imported, no corpus is
imported, and no database is reachable** — `apps/worker` runs the agents over the corpus and
hands the results here as `Claim`s, which is the same split D-054 draws for the audit path and
D-025 draws for persistence. A fitting module that could open a session or call an agent would
make "reproducible from the calibration split and a recorded corpus hash" an honour system.

The order of operations is §6, and it is not negotiable:

1. `fit.fit_ratios` on the **calibration** split, and nothing else.
2. `threshold.select` on the **validation** split, with the ratios already frozen.
3. The **test** split is untouched until Chapter 18, where it is evaluated exactly once.
"""

from codesheriff_engine.calibration.artifact import (
    ARTIFACT_FILENAME,
    CALIBRATION_PATH_ENV,
    PACKAGED_ARTIFACT,
    CalibrationArtifact,
    CalibrationError,
    active_artifact,
    artifact_path,
    build,
)
from codesheriff_engine.calibration.fit import (
    LAPLACE_ALPHA,
    SILENCE_CEILING,
    CellFit,
    Fit,
    WitnessFit,
    fit_ratios,
    fit_witness,
)
from codesheriff_engine.calibration.metrics import (
    CalibrationMetrics,
    ReliabilityBin,
    brier_score,
    evaluate,
    expected_calibration_error,
    reliability_bins,
)
from codesheriff_engine.calibration.observations import (
    Claim,
    ObservationSet,
    RunProvenance,
    claims_for_case,
    iter_claims,
)
from codesheriff_engine.calibration.prior import DEFAULT_BASE_RATE, Prior, importance_weights
from codesheriff_engine.calibration.scoring import posteriors_for, weights_for
from codesheriff_engine.calibration.threshold import (
    SweepPoint,
    ThresholdSelection,
    select,
    sweep,
)

__all__ = [
    "ARTIFACT_FILENAME",
    "CALIBRATION_PATH_ENV",
    "DEFAULT_BASE_RATE",
    "LAPLACE_ALPHA",
    "PACKAGED_ARTIFACT",
    "SILENCE_CEILING",
    "CalibrationArtifact",
    "CalibrationError",
    "CalibrationMetrics",
    "CellFit",
    "Claim",
    "Fit",
    "ObservationSet",
    "Prior",
    "ReliabilityBin",
    "RunProvenance",
    "SweepPoint",
    "ThresholdSelection",
    "WitnessFit",
    "active_artifact",
    "artifact_path",
    "brier_score",
    "build",
    "claims_for_case",
    "evaluate",
    "expected_calibration_error",
    "fit_ratios",
    "fit_witness",
    "importance_weights",
    "iter_claims",
    "posteriors_for",
    "reliability_bins",
    "select",
    "sweep",
    "weights_for",
]
