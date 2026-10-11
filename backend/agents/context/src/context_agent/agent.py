"""The context witness: what this repository already accepted, and what this change drops.

Its basis for a decision is **precedent** — merged code from this repository and no other —
which is why it can see an authorization bug that has no syntactic pattern to prove and no
sink to reach. Its documented failure mode is a repository with no relevant history, and that
failure is loud here: an abstention, under its own name, at a likelihood ratio of exactly 1.0.

Chapter 12 replaced everything below the interface. What was here (`AUDIT.md` 0.2, 3.7, 3.8):

**Four substring tests for `stripe_charge`**, with no retrieval in the reasoning at all. The
retrieved document was a gate and a 300-character excerpt; nothing it contained could change
what was detected. The finding it built was keyed off a string literal, so it could never
collide with another agent's key and the anchor filter deleted it every time (`AUDIT.md` 1.5).

**One global vector collection for every repository**, with `unit.repo` neither queried nor
stored, so one repository's diffs could surface as another's review context and no filter
could be added without a full re-ingest. Scoping is now structural: the retriever is built
against one repository and has no parameter that could name another.

**Embeddings that silently degraded to MD5 term hashing** when `sentence-transformers` was
absent — which it was, from this package's own dependencies — with no log line and no
abstention. This package no longer embeds anything. The model lives with the store in
`apps/worker`, and a retriever that cannot embed raises `RetrievalUnavailableError`, which
lands here as an abstention that names the failure.

**It corroborates; it does not solo** (D-012). Evidence is emitted under `unit.key_for(cwe)`,
the key any agent derives for this unit and CWE, so it lands on an existing finding rather
than opening one of its own. That is not a courtesy — with the provisional ratios, its
strongest detection takes a 0.05 prior to 0.18 against a 0.70 threshold, so a finding it
raised alone could never alert. A witness that can only corroborate must key like one.
"""

from __future__ import annotations

import logging

from codesheriff_contracts import Artifact, ChangeUnit, Evidence
from context_agent.classify import COVERED_CWES
from context_agent.config import AGENT_ID, AGENT_VERSION, ContextConfig
from context_agent.precedent import (
    NoPrecedentRetriever,
    Precedent,
    PrecedentRetriever,
    RetrievalUnavailableError,
)
from context_agent.regression import MissingControl, missing_controls, score_for

logger = logging.getLogger(__name__)

MAX_SUPPORTING_IN_ARTIFACT = 3
"""How many merged excerpts to name in an artifact.

Bounded because artifacts are persisted (D-027) and because a reader checking a claim about
precedent needs two or three examples, not the whole history.
"""

EXCERPT_BUDGET = 400
"""Characters of a merged excerpt reproduced in an artifact.

Source code is never persisted in full (D-027, `PROJECT_CONTEXT.md` §5 on security); what a
finding needs is enough of the accepted version to see the guard on it.
"""


class ContextAgent:
    """Repository-precedent analyser. Never raises; abstains with a distinct reason instead."""

    def __init__(
        self,
        config: ContextConfig | None = None,
        retriever: PrecedentRetriever | None = None,
    ) -> None:
        self.config = config or ContextConfig.load()
        self.agent_id = AGENT_ID
        self.agent_version = AGENT_VERSION

        # No retriever means no precedent, and the agent says so on every unit. It must never
        # fall back to a store of its own: an agent that assembled its own history would be
        # answering questions about a repository nobody pointed it at, and its silence would
        # argue — below a likelihood ratio of 1.0 — that code it never had context for is fine.
        if retriever is None:
            logger.warning(
                "context.rag has no precedent retriever and will abstain on every unit. "
                "apps/worker injects the pgvector-backed one; expect one fewer witness."
            )
        self.retriever: PrecedentRetriever = retriever or NoPrecedentRetriever()

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        """This agent's statement about one unit. Always at least one, never an exception.

        Runs blind (D-008): one argument, no anchors. The superseded agent abstained with
        `no_anchor` unless it was handed the static agent's finding keys, which made it
        architecturally incapable of contributing anything the static agent had not already
        found — and correlated the two witnesses whose independence the fusion math assumes.
        """
        try:
            return self._analyse(unit)
        except Exception as exc:
            logger.exception("unhandled exception in context.rag on unit %s", unit.unit_id)
            return [self._abstain(unit, "runtime_error", f"{type(exc).__name__}: {exc}"[:400])]

    # -- the analysis ----------------------------------------------------------------------

    def _analyse(self, unit: ChangeUnit) -> list[Evidence]:
        if len(unit.post_src.encode("utf-8")) > self.config.max_unit_bytes:
            return [
                self._abstain(
                    unit,
                    "unit_too_large",
                    f"{len(unit.post_src)} characters exceeds the {self.config.max_unit_bytes}"
                    " byte budget; a control surface mined from a unit this size is not a claim"
                    " about a guard (D-015).",
                )
            ]

        try:
            retrieved = self.retriever.retrieve(unit, self.config.top_k)
        except RetrievalUnavailableError as exc:
            # Loud, and distinct from "no history" (`AUDIT.md` 3.8). A store or an embedding
            # model that is down must not be reported as a repository that happens to be new.
            logger.error("precedent retrieval unavailable for %s: %s", unit.unit_id, exc)
            return [self._abstain(unit, "retrieval_unavailable", str(exc)[:400])]

        if not retrieved:
            return [
                self._abstain(
                    unit,
                    "no_precedent",
                    "This repository holds no merged precedent to compare against.",
                )
            ]

        relevant = [p for p in retrieved if p.similarity >= self.config.min_similarity]
        if not relevant:
            return [
                self._abstain(
                    unit,
                    "no_relevant_precedent",
                    f"{len(retrieved)} excerpt(s) retrieved, none within "
                    f"{self.config.min_similarity} similarity of this unit.",
                )
            ]

        missing = missing_controls(unit, relevant)
        if not missing:
            # Retrieval worked and nothing this witness reports has regressed. SILENCE, never
            # `[]` — an empty list from a successful analysis is indistinguishable from a
            # failure, and it throws away the one statement that can lower a posterior (D-005).
            return [
                Evidence.silence(
                    agent_id=self.agent_id,
                    agent_version=self.agent_version,
                    unit_id=unit.unit_id,
                    covered_cwes=COVERED_CWES,
                    explanation=(
                        f"Compared against {len(relevant)} merged excerpt(s) from this "
                        "repository; no authorization control established there is absent here."
                    ),
                )
            ]

        return self._detections(unit, missing)

    def _detections(self, unit: ChangeUnit, missing: list[MissingControl]) -> list[Evidence]:
        """One detection per CWE, not one per control.

        Two guards missing from the same function is one authorization failure with two pieces
        of evidence behind it, and fusion groups by `finding_key` — which is derived from the
        CWE. Emitting twice would put two statements from one witness onto one finding, and
        `bayes.py` combining them is a factor this witness did not earn.
        """
        grouped: dict[str, list[MissingControl]] = {}
        for item in missing:
            grouped.setdefault(item.cwe, []).append(item)

        evidence: list[Evidence] = []
        for cwe in sorted(grouped):
            items = grouped[cwe]
            best = max(items, key=score_for)
            evidence.append(
                Evidence.detection(
                    agent_id=self.agent_id,
                    agent_version=self.agent_version,
                    unit_id=unit.unit_id,
                    # Through the unit, never assembled by hand (D-019). A key built from a
                    # string literal is the AUDIT.md 1.5 bug: it collides with nothing, so the
                    # finding is a permanent singleton and no Bayesian update ever happens.
                    finding_key=unit.key_for(cwe),
                    cwe=cwe,
                    raw_score=score_for(best),
                    confidence=0.9,
                    explanation=self._explain(unit, items),
                    artifacts=[self._artifact(item) for item in items],
                )
            )
        return evidence

    def _explain(self, unit: ChangeUnit, items: list[MissingControl]) -> str:
        """Plain words, no file path (D-050).

        A path is chosen by whoever opened the pull request and this text reaches a rendered
        comment. The symbol is this repository's own and is safe to name; paths belong on the
        dashboard, behind escaping.
        """
        controls = ", ".join(item.control.describe() for item in items)
        first = items[0]
        if first.same_symbol:
            basis = (
                f"this repository merged {unit.qualified_symbol} carrying it in "
                f"#{first.supporting[0].pr_number}"
            )
        else:
            others = sorted({p.qualified_symbol for p in first.supporting})
            basis = f"{len(others)} merged sibling(s) apply it: {', '.join(others)}"
        return (
            f"{unit.qualified_symbol} does not apply {controls}, which this repository's own "
            f"merged history establishes for code of this kind — {basis}."
        )

    def _artifact(self, item: MissingControl) -> Artifact:
        """The precedent behind one claim, so a reader can check it.

        Excerpts are clipped here as well as at write time. `codesheriff_storage` caps what it
        persists (D-027), but an artifact also travels to a rendered comment, and the budget
        should not be enforced only by the last component to touch it.
        """
        return Artifact(
            artifact_type="precedent_regression",
            content={
                "control": item.control.describe(),
                "control_kind": item.control.kind.value,
                "established_by_same_symbol": item.same_symbol,
                "supporting_symbols": item.support,
                "precedent": [
                    {
                        "pr_number": p.pr_number,
                        "qualified_symbol": p.qualified_symbol,
                        "similarity": round(p.similarity, 4),
                        "excerpt": p.accepted_src[:EXCERPT_BUDGET],
                    }
                    for p in _distinct_by_symbol(item.supporting)[:MAX_SUPPORTING_IN_ARTIFACT]
                ],
            },
        )

    def _abstain(self, unit: ChangeUnit, reason: str, explanation: str) -> Evidence:
        return Evidence.abstention(
            agent_id=self.agent_id,
            agent_version=self.agent_version,
            unit_id=unit.unit_id,
            reason=reason,
            explanation=explanation,
        )


def _distinct_by_symbol(precedents: tuple[Precedent, ...]) -> list[Precedent]:
    """One excerpt per symbol, closest first. Three merges of the same function are one witness."""
    seen: set[str] = set()
    ordered: list[Precedent] = []
    for precedent in sorted(precedents, key=lambda p: -p.similarity):
        if precedent.qualified_symbol in seen:
            continue
        seen.add(precedent.qualified_symbol)
        ordered.append(precedent)
    return ordered
