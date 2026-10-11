"""CodeSheriff fusion and extraction engine.

No `Orchestrator` here any more. Running agents moved to `apps/worker`, which is where
`CLAUDE.md` says the pipeline and all four agents live, and which is the only process that
declares them as dependencies. The engine reached them by `try: import static_agent` — an
undeclared runtime dependency that made a fusion package able to load an LLM client, and
put the layering the import-linter contracts describe one import away from being false.

What is left is what the engine is for: deciding what a change unit is, and turning
evidence into a posterior. Neither needs a credential, a socket or a database session,
which is what lets the calibration harness run both over the corpus with nothing configured.

Chapter 14 added one thing: `codesheriff_engine.calibration`, which fits the numbers fusion
multiplies with. It imports no agent and opens no session either — it takes labelled claims and
returns a table — so the reproducibility §6 asks for is a property of the code rather than a
promise about how it is used.
"""

from codesheriff_contracts import Artifact, ChangeUnit, Evidence, finding_key
from codesheriff_engine.calibration import CalibrationArtifact, CalibrationError, active_artifact
from codesheriff_engine.config import EngineConfig, WitnessRatios
from codesheriff_engine.fusion import (
    WITNESSES,
    FusionResult,
    Stance,
    WitnessContribution,
    compute_bayesian_fusion,
    fuse_all_evidence,
    witness_for,
)

__version__ = "0.1.0"

__all__ = [
    "WITNESSES",
    "Artifact",
    "CalibrationArtifact",
    "CalibrationError",
    "ChangeUnit",
    "EngineConfig",
    "Evidence",
    "FusionResult",
    "Stance",
    "WitnessContribution",
    "WitnessRatios",
    "active_artifact",
    "compute_bayesian_fusion",
    "finding_key",
    "fuse_all_evidence",
    "witness_for",
]
