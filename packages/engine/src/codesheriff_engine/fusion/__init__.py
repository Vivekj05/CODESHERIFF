"""Bayesian odds fusion.

`debate.py` used to live here and is deleted rather than ported (D-009). It overwrote the
fused posterior with its own number, which destroys calibration on exactly the contested
cases the debate exists for and makes the step unmeasurable (`AUDIT.md` 2.2); and because
no LLM key is configured by default, its *normal* path was substring matching over
lowercased source, in which `"int("` — a substring of `print(` — counted as a sanitizer
(`AUDIT.md` 2.3). Debate returns as a witness that emits its own evidence, with the LLM
client that runs it, in Chapter 11.
"""

from codesheriff_engine.fusion.bayes import (
    ABSTENTION_LR,
    FusionResult,
    Stance,
    WitnessContribution,
    compute_bayesian_fusion,
    fuse_all_evidence,
    normalize_evidence,
)
from codesheriff_engine.fusion.witnesses import (
    CONTEXT,
    RUNTIME,
    SEMANTIC,
    STRUCTURAL,
    WITNESS_OF_AGENT,
    WITNESSES,
    UnknownAgentError,
    agents_of,
    witness_for,
)

__all__ = [
    "ABSTENTION_LR",
    "CONTEXT",
    "RUNTIME",
    "SEMANTIC",
    "STRUCTURAL",
    "WITNESSES",
    "WITNESS_OF_AGENT",
    "FusionResult",
    "Stance",
    "UnknownAgentError",
    "WitnessContribution",
    "agents_of",
    "compute_bayesian_fusion",
    "fuse_all_evidence",
    "normalize_evidence",
    "witness_for",
]
