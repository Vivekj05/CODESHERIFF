"""Bayesian Odds & Likelihood Ratio Fusion Engine for CodeSheriff."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from codesheriff_contracts import Evidence, EvidenceKind
from codesheriff_engine.config import DEFAULT_LIKELIHOOD_TABLE, FALLBACK_LIKELIHOOD_TIER


class FusionResult(BaseModel):
    """Aggregated output from Bayesian fusion over all agent evidence for a finding."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    finding_key: str
    posterior_probability: float
    is_alert_worthy: bool
    evidence_list: list[Evidence]
    consensus_rationale: str = ""
    cwe: str | None = None
    title: str | None = None
    severity: str | None = None
    file: str | None = None
    line_numbers: list[int] = Field(default_factory=list)


def normalize_evidence(evidence_list: list[Any]) -> list[Evidence]:
    """Coerce inbound items to the shared Evidence contract.

    This used to reconcile four vendored, separately-evolving Evidence classes. There
    is now exactly one contract package, so the only real work left is validating
    dicts that arrive over the wire.

    It no longer swallows failures. The previous `except Exception: pass` discarded
    malformed evidence silently (AUDIT.md 2.7) — evidence vanishing without trace is
    the one thing a calibration claim cannot survive.
    """
    normalized: list[Evidence] = []
    for ev in evidence_list:
        if isinstance(ev, Evidence):
            normalized.append(ev)
        elif isinstance(ev, dict):
            normalized.append(Evidence.model_validate(ev))
        elif hasattr(ev, "model_dump"):
            normalized.append(Evidence.model_validate(ev.model_dump()))
        else:
            raise TypeError(
                f"Cannot normalise {type(ev).__name__} into Evidence. Agents must return "
                "codesheriff_contracts.Evidence; there is no vendored variant any more."
            )
    return normalized


def get_likelihood_ratio(
    agent_id: str,
    score: float,
    likelihood_table: dict[str, dict[str, float]] | None = None,
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
    evidence_list: list[Any],
    prior_p: float = 0.05,
    alert_threshold: float = 0.70,
    likelihood_table: dict[str, dict[str, float]] | None = None,
) -> FusionResult:
    """Compute posterior vulnerability probability using Bayesian Odds updating."""
    normalized_list = normalize_evidence(evidence_list)

    # Only DETECTIONs move the odds today.
    #
    # NOT YET CONFORMANT (AUDIT.md 1.4, D-007): §5 requires fusion to iterate ALL
    # agents, applying LR < 1.0 for a SILENCE that covers the finding's CWE and
    # exactly 1.0 for an ABSTENTION. Iterating only the agents that spoke means the
    # odds can only ever increase. Wiring that in needs fitted ratios, so it lands
    # with the calibration work — PLAN.md Chapter 9 and Chapter 14. Chapter 2 makes
    # the evidence to do it with expressible; it does not yet consume it.
    active_evidence = [ev for ev in normalized_list if ev.kind is EvidenceKind.DETECTION]

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
    line_numbers: list[int] = []
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
    evidence_list: list[Any],
    prior_p: float = 0.05,
    alert_threshold: float = 0.70,
    likelihood_table: dict[str, dict[str, float]] | None = None,
) -> list[FusionResult]:
    """Group all raw evidence from multiple agents by finding_key and compute Bayesian fusion."""
    if not evidence_list:
        return []

    normalized_list = normalize_evidence(evidence_list)

    # Group evidence by finding_key
    grouped: dict[str, list[Evidence]] = {}
    non_detections: list[Evidence] = []

    for ev in normalized_list:
        if ev.kind is EvidenceKind.DETECTION and ev.finding_key is not None:
            grouped.setdefault(ev.finding_key, []).append(ev)
        else:
            # SILENCE and ABSTENTION are statements about the unit, not about one
            # finding, so they carry no key to group under.
            non_detections.append(ev)

    results: list[FusionResult] = []

    for key, ev_group in grouped.items():
        result = compute_bayesian_fusion(
            finding_key=key,
            evidence_list=ev_group,
            prior_p=prior_p,
            alert_threshold=alert_threshold,
            likelihood_table=likelihood_table,
        )
        results.append(result)

    # No detections anywhere: report the unit at the prior.
    if not results and non_detections:
        results.append(
            compute_bayesian_fusion(
                finding_key="abstention:all_agents",
                evidence_list=non_detections,
                prior_p=prior_p,
                alert_threshold=alert_threshold,
                likelihood_table=likelihood_table,
            )
        )

    # Sort findings by posterior probability descending (most critical first)
    results.sort(key=lambda r: r.posterior_probability, reverse=True)
    return results
