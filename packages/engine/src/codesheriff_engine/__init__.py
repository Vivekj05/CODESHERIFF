"""CodeSheriff Fusion & Integration Engine package."""

from codesheriff_engine.contracts import Artifact, ChangeUnit, Evidence, finding_key
from codesheriff_engine.config import EngineConfig
from codesheriff_engine.fusion.bayes import FusionResult, compute_bayesian_fusion, fuse_all_evidence
from codesheriff_engine.orchestrator import Orchestrator

__version__ = "0.1.0"

__all__ = [
    "Artifact",
    "ChangeUnit",
    "Evidence",
    "finding_key",
    "EngineConfig",
    "FusionResult",
    "compute_bayesian_fusion",
    "fuse_all_evidence",
    "Orchestrator",
]
