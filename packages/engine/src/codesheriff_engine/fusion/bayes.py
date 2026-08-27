"""Bayesian Odds & Likelihood Ratio Fusion Engine for CodeSheriff."""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from codesheriff_engine.config import DEFAULT_LIKELIHOOD_TABLE, FALLBACK_LIKELIHOOD_TIER
from codesheriff_engine.contracts import Evidence


class FusionResult(BaseModel):
    """Aggregated output from Bayesian fusion over all agent evidence for a finding."""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    finding_key: str
    posterior_probability: float
    is_alert_worthy: bool
    evidence_list: List[Evidence]
    consensus_rationale: str = ""
    cwe: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    file: Optional[str] = None
    line_numbers: List[int] = Field(default_factory=list)


def normalize_evidence(evidence_list: List[Any]) -> List[Evidence]:
    """Normalize Evidence instances across vendored agent packages into engine Evidence models."""
    normalized: List[Evidence] = []
    for ev in evidence_list:
        if isinstance(ev, Evidence):
            normalized.append(ev)
        elif hasattr(ev, "model_dump"):
            normalized.append(Evidence.model_validate(ev.model_dump()))
        elif hasattr(ev, "dict"):
            normalized.append(Evidence.model_validate(ev.dict()))
        elif isinstance(ev, dict):
            normalized.append(Evidence.model_validate(ev))
        else:
            # Attempt best-effort attribute copy
            try:
                data = {
                    "agent_id": getattr(ev, "agent_id", "unknown"),
                    "agent_version": getattr(ev, "agent_version", "0.0.0"),
                    "unit_id": getattr(ev, "unit_id", "unknown"),
                    "finding_key": getattr(ev, "finding_key", "unknown"),
                    "cwe": getattr(ev, "cwe", None),
                    "raw_score": getattr(ev, "raw_score", 0.0),
                    "confidence": getattr(ev, "confidence", 1.0),
                    "explanation": getattr(ev, "explanation", ""),
                    "artifacts": [
                        a.model_dump() if hasattr(a, "model_dump") else a
                        for a in getattr(ev, "artifacts", [])
                    ],
                    "abstained": getattr(ev, "abstained", False),
                    "abstain_reason": getattr(ev, "abstain_reason", None),
                }
                normalized.append(Evidence.model_validate(data))
            except Exception:
                pass
    return normalized


def get_likelihood_ratio(
    agent_id: str,
    score: float,
    likelihood_table: Optional[Dict[str, Dict[str, float]]] = None,
) -> float:
    """Return calibrated Likelihood Ratio (LR) for an agent given its raw confidence score."""
    table = (likelihood_table or DEFAULT_LIKELIHOOD_TABLE).get(agent_id, FALLBACK_LIKELIHOOD_TIER)

    if score >= 0.8:
        return table.get("high", 3.0)
    elif score >= 0.5:
        return table.get("medium", 1.5)
    else:
        return table.get("low", 0.8)


def compute_bayesian_fusion(
    finding_key: str,
    evidence_list: List[Any],
    prior_p: float = 0.05,
    alert_threshold: float = 0.70,
    likelihood_table: Optional[Dict[str, Dict[str, float]]] = None,
) -> FusionResult:
    """Compute posterior vulnerability probability using Bayesian Odds updating."""
    normalized_list = normalize_evidence(evidence_list)

    # Filter active (non-abstained) evidence
    active_evidence = [
        ev for ev in normalized_list 
        if not ev.abstained and not ev.finding_key.startswith("abstain:")
    ]

    # If no active evidence exists (all agents abstained or no findings)
    if not active_evidence:
        return FusionResult(
            finding_key=finding_key,
            posterior_probability=round(prior_p, 4),
            is_alert_worthy=False,
            evidence_list=normalized_list,
            consensus_rationale="All agents abstained or returned zero findings for this unit.",
        )

    # Prior odds: O = P0 / (1 - P0)
    clamped_prior = max(0.001, min(0.999, prior_p))
    prior_odds = clamped_prior / (1.0 - clamped_prior)
    current_odds = prior_odds

    for ev in active_evidence:
        lr = get_likelihood_ratio(ev.agent_id, ev.raw_score, likelihood_table)
        current_odds *= lr

    # Posterior probability: P = Odds / (1 + Odds)
    posterior_p = current_odds / (1.0 + current_odds)
    posterior_p = max(0.0001, min(0.9999, posterior_p))
    is_alert = posterior_p >= alert_threshold

    # Extract metadata (CWE, title, severity) from the highest-scoring evidence
    sorted_by_score = sorted(active_evidence, key=lambda e: e.raw_score, reverse=True)
    primary_ev = sorted_by_score[0]

    # Derive severity estimate
    severity = "medium"
    if posterior_p >= 0.85:
        severity = "critical"
    elif posterior_p >= 0.70:
        severity = "high"
    elif posterior_p >= 0.40:
        severity = "medium"
    else:
        severity = "low"

    # Extract title and lines from artifacts if available
    title = f"{primary_ev.cwe or 'Security Flaw'}: {primary_ev.explanation[:60]}"
    line_numbers: List[int] = []
    for ev in active_evidence:
        for art in ev.artifacts:
            art_content = getattr(art, "content", art)
            if isinstance(art_content, dict) and "steps" in art_content:
                for step in art_content.get("steps", []):
                    if "line" in step and step["line"] not in line_numbers:
                        line_numbers.append(step["line"])

    return FusionResult(
        finding_key=finding_key,
        posterior_probability=round(posterior_p, 4),
        is_alert_worthy=is_alert,
        evidence_list=normalized_list,
        consensus_rationale="",
        cwe=primary_ev.cwe,
        title=title,
        severity=severity,
        file=None,
        line_numbers=sorted(line_numbers),
    )


def fuse_all_evidence(
    evidence_list: List[Any],
    prior_p: float = 0.05,
    alert_threshold: float = 0.70,
    likelihood_table: Optional[Dict[str, Dict[str, float]]] = None,
) -> List[FusionResult]:
    """Group all raw evidence from multiple agents by finding_key and compute Bayesian fusion."""
    if not evidence_list:
        return []

    normalized_list = normalize_evidence(evidence_list)

    # Group evidence by finding_key
    grouped: Dict[str, List[Evidence]] = {}
    abstentions: List[Evidence] = []

    for ev in normalized_list:
        if ev.abstained or ev.finding_key.startswith("abstain:"):
            abstentions.append(ev)
        else:
            grouped.setdefault(ev.finding_key, []).append(ev)

    results: List[FusionResult] = []

    for key, ev_group in grouped.items():
        result = compute_bayesian_fusion(
            finding_key=key,
            evidence_list=ev_group,
            prior_p=prior_p,
            alert_threshold=alert_threshold,
            likelihood_table=likelihood_table,
        )
        results.append(result)

    # If there are no positive findings at all, but there were abstentions
    if not results and abstentions:
        results.append(
            compute_bayesian_fusion(
                finding_key="abstention:all_agents",
                evidence_list=abstentions,
                prior_p=prior_p,
                alert_threshold=alert_threshold,
                likelihood_table=likelihood_table,
            )
        )

    # Sort findings by posterior probability descending (most critical first)
    results.sort(key=lambda r: r.posterior_probability, reverse=True)
    return results
