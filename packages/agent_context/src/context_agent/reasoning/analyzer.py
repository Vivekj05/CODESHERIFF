"""Cross-PR security control regression evaluator.

NON-CONFORMANT: the four substring tests below are not RAG reasoning — retrieved
documents never influence what is detected (AUDIT.md 0.2, 3.7, 3.8). PLAN.md
Chapter 12 replaces this module. Chapter 2 only makes it contract-legal.
"""

from __future__ import annotations

import logging

from codesheriff_contracts import Artifact, ChangeUnit, Evidence

logger = logging.getLogger(__name__)


def evaluate_cross_pr_regression(
    unit: ChangeUnit,
    past_pr_docs: list[str],
    agent_id: str = "context.rag",
    agent_version: str = "0.1.0",
) -> list[Evidence]:
    """Evaluate whether this unit bypasses a security invariant set by a past PR."""
    evidence_list: list[Evidence] = []
    if not past_pr_docs:
        return evidence_list

    post_src = unit.post_src

    for doc in past_pr_docs:
        # Check for CSRF / Rate Limit wrapper bypasses
        if (
            ("require_csrf_token" in doc or "rate_limit" in doc or "stripe_charge" in doc)
            and "stripe_charge" in post_src
            and not ("@require_csrf_token" in post_src and "@rate_limit" in post_src)
        ):
            sink_expr = "stripe_charge(request.json)"
            # Key through the unit (D-004/D-012). Built from a string literal, this
            # key could never collide with any other agent's, so the finding was
            # deleted by the anchor filter every time and the agent contributed
            # literally nothing (AUDIT.md 1.5).
            f_key = unit.key_for("CWE-862")

            explanation = (
                f"Cross-PR Security Control Bypass (CWE-862): Function '{unit.symbol}' calls "
                f"'stripe_charge()' directly, bypassing security controls "
                f"(@require_csrf_token, @rate_limit) "
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

            ev = Evidence.detection(
                agent_id=agent_id,
                agent_version=agent_version,
                unit_id=unit.unit_id,
                finding_key=f_key,
                cwe="CWE-862",
                raw_score=0.92,
                confidence=0.95,
                explanation=explanation,
                artifacts=artifacts,
            )
            evidence_list.append(ev)

    return evidence_list
