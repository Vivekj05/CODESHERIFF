"""Fusion module containing Bayesian odds updates and multi-agent debate synthesis."""

from codesheriff_engine.fusion.bayes import (
    FusionResult,
    compute_bayesian_fusion,
    fuse_all_evidence,
    get_likelihood_ratio,
)
from codesheriff_engine.fusion.debate import resolve_agent_conflict

__all__ = [
    "FusionResult",
    "compute_bayesian_fusion",
    "fuse_all_evidence",
    "get_likelihood_ratio",
    "resolve_agent_conflict",
]
