"""CodeSheriff fusion and extraction engine.

No `Orchestrator` here any more. Running agents moved to `apps/worker`, which is where
`CLAUDE.md` says the pipeline and all four agents live, and which is the only process that
declares them as dependencies. The engine reached them by `try: import static_agent` — an
undeclared runtime dependency that made a fusion package able to load an LLM client, and
put the layering the import-linter contracts describe one import away from being false.

What is left is what the engine is for: deciding what a change unit is, and turning
evidence into a posterior. Neither needs a credential, a socket or a database session,
which is what lets Chapter 14 run both over the corpus with nothing configured.
"""

from codesheriff_contracts import Artifact, ChangeUnit, Evidence, finding_key
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
    "ChangeUnit",
    "EngineConfig",
    "Evidence",
    "FusionResult",
    "Stance",
    "WitnessContribution",
    "WitnessRatios",
    "compute_bayesian_fusion",
    "finding_key",
    "fuse_all_evidence",
    "witness_for",
]
