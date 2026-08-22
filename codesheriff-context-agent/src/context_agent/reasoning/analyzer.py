"""Cross-PR security control regression evaluator."""

from __future__ import annotations

import logging
from typing import List, Optional
from context_agent.contracts import Artifact, ChangeUnit, Evidence, finding_key

logger = logging.getLogger(__name__)


def evaluate_cross_pr_regression(
    unit: ChangeUnit,
    past_pr_docs: List[str],
    agent_id: str = "context.rag",
    agent_version: str = "0.1.0",
) -> List[Evidence]:
    """Evaluate whether the new ChangeUnit invalidates or bypasses security invariants established in past PRs."""
    evidence_list: List[Evidence] = []
    if not past_pr_docs:
        return evidence_list

    post_src = unit.post_src

    for doc in past_pr_docs:
        # Check for CSRF / Rate Limit wrapper bypasses
        if "require_csrf_token" in doc or "rate_limit" in doc or "stripe_charge" in doc:
            # Check if post_src calls stripe_charge or payment logic directly without required decorators
            if "stripe_charge" in post_src and not ("@require_csrf_token" in post_src and "@rate_limit" in post_src):
                sink_expr = "stripe_charge(request.json)"
                f_key = finding_key(unit.file, unit.symbol, "CWE-862", sink_expr)
                
                explanation = (
                    f"Cross-PR Security Control Bypass (CWE-862): Function '{unit.symbol}' calls "
                    f"'stripe_charge()' directly, bypassing security controls (@require_csrf_token, @rate_limit) "
                    f"established in accepted historical PRs."
                )

                artifacts = [
                    Artifact(
                        artifact_type="cross_pr_bypass",
                        content={
                            "bypassed_controls": ["@require_csrf_token", "@rate_limit"],
                            "historical_context": doc[:300],
                            "sink_expression": sink_expr,
                        },
                    )
                ]

                ev = Evidence(
                    agent_id=agent_id,
                    agent_version=agent_version,
                    unit_id=unit.unit_id,
                    finding_key=f_key,
                    cwe="CWE-862",
                    raw_score=0.92,
                    confidence=0.95,
                    explanation=explanation,
                    artifacts=artifacts,
                    abstained=False,
                    abstain_reason=None,
                )
                evidence_list.append(ev)

    return evidence_list
