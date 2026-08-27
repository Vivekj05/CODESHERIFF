"""Main RAG ContextAgent analyzer implementation."""

from __future__ import annotations

import logging

from codesheriff_contracts import IN_SCOPE_CWES, ChangeUnit, Evidence
from context_agent.config import ContextConfig
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.store import VectorStore
from context_agent.reasoning.analyzer import evaluate_cross_pr_regression
from context_agent.retrieval.search import retrieve_similar_prs

logger = logging.getLogger(__name__)

#: What repository precedent can actually evidence: the removal of an access
#: control that earlier accepted PRs established. No taint path shows these,
#: which is the whole reason this agent exists (D-006).
COVERED_CWES: frozenset[str] = frozenset({"CWE-862", "CWE-639"}) & IN_SCOPE_CWES


class ContextAgent:
    """RAG-powered cross-PR security regression reviewer agent for CodeSheriff."""

    def __init__(
        self,
        config: ContextConfig | None = None,
        embedder: LocalEmbedder | None = None,
        store: VectorStore | None = None,
    ) -> None:
        self.config = config or ContextConfig.load()
        self.agent_id = self.config.agent_id
        self.agent_version = self.config.agent_version
        self.embedder = embedder or LocalEmbedder(self.config.embedding_model)
        self.store = store or VectorStore(self.config.chroma_db_dir)

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        """Analyse a ChangeUnit against RAG memory for cross-PR security regressions.

        Runs blind: no `anchors` parameter (D-008). The agent previously abstained
        with `no_anchor` unless handed the static agent's finding keys, which made it
        architecturally incapable of contributing anything the static agent had not
        already found — and correlated the two.

        It still corroborates rather than solos (D-012): evidence is emitted under the
        key any agent would derive for this unit and CWE, so it lands on an existing
        finding when one exists instead of opening a case of its own.

        Guarantees zero unhandled exceptions.
        """
        try:
            # 1. Cold Start Check (PR #1 handling)
            if self.store.count() == 0:
                return [
                    Evidence.abstention(
                        agent_id=self.agent_id,
                        agent_version=self.agent_version,
                        unit_id=unit.unit_id,
                        reason="no_historical_prs",
                        explanation="Vector database is empty (1st PR in repository).",
                    )
                ]

            # 3. Vector Retrieval of Top-K Past PRs
            search_res = retrieve_similar_prs(
                unit=unit,
                store=self.store,
                embedder=self.embedder,
                top_k=self.config.top_k,
            )

            documents = search_res.get("documents", [[]])[0]
            distances = search_res.get("distances", [[]])[0]

            if not documents:
                return [
                    Evidence.abstention(
                        agent_id=self.agent_id,
                        agent_version=self.agent_version,
                        unit_id=unit.unit_id,
                        reason="no_relevant_past_prs",
                        explanation="No historically related PRs found in RAG memory.",
                    )
                ]

            # 4. Relevance distance filter
            if distances and distances[0] > (1.0 - self.config.similarity_threshold):
                return [
                    Evidence.abstention(
                        agent_id=self.agent_id,
                        agent_version=self.agent_version,
                        unit_id=unit.unit_id,
                        reason="no_relevant_past_prs",
                        explanation="Retrieved PRs fell below semantic relevance threshold.",
                    )
                ]

            # 5. Cross-PR logic evaluation
            evidence_list = evaluate_cross_pr_regression(
                unit=unit,
                past_pr_docs=documents,
                agent_id=self.agent_id,
                agent_version=self.agent_version,
            )

            # 6. Retrieval succeeded and nothing regressed: SILENCE, not [] (D-005).
            #    This agent reasons from repository precedent, so its silence speaks
            #    only to the control-bypass CWEs it can recognise (D-006).
            if not evidence_list:
                return [
                    Evidence.silence(
                        agent_id=self.agent_id,
                        agent_version=self.agent_version,
                        unit_id=unit.unit_id,
                        covered_cwes=COVERED_CWES,
                        explanation="Relevant precedent retrieved; no security control regressed.",
                    )
                ]

            return evidence_list

        except Exception as e:
            logger.exception("Unhandled runtime exception in ContextAgent")
            return [
                Evidence.abstention(
                    agent_id=self.agent_id,
                    agent_version=self.agent_version,
                    unit_id=unit.unit_id,
                    reason="runtime_error",
                    explanation=f"Unhandled exception during context analysis: {e}",
                )
            ]
