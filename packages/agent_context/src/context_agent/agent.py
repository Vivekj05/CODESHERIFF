"""Main RAG ContextAgent analyzer implementation."""

from __future__ import annotations

import logging
from typing import List, Optional, Set
from context_agent.config import ContextConfig
from context_agent.contracts import ChangeUnit, Evidence
from context_agent.rag.embedder import LocalEmbedder
from context_agent.rag.store import VectorStore
from context_agent.reasoning.analyzer import evaluate_cross_pr_regression
from context_agent.retrieval.search import retrieve_similar_prs

logger = logging.getLogger(__name__)


class ContextAgent:
    """RAG-powered cross-PR security regression reviewer agent for CodeSheriff."""

    def __init__(
        self,
        config: Optional[ContextConfig] = None,
        embedder: Optional[LocalEmbedder] = None,
        store: Optional[VectorStore] = None,
    ) -> None:
        self.config = config or ContextConfig.load()
        self.agent_id = self.config.agent_id
        self.agent_version = self.config.agent_version
        self.embedder = embedder or LocalEmbedder(self.config.embedding_model)
        self.store = store or VectorStore(self.config.chroma_db_dir)

    def analyze(
        self,
        unit: ChangeUnit,
        anchors: Optional[Set[str]] = None,
    ) -> List[Evidence]:
        """Analyze a ChangeUnit against RAG memory for cross-PR security regressions. Guarantees zero unhandled exceptions."""
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

            # 2. Anchor requirement check
            if anchors is None or len(anchors) == 0:
                return [
                    Evidence.abstention(
                        agent_id=self.agent_id,
                        agent_version=self.agent_version,
                        unit_id=unit.unit_id,
                        reason="no_anchor",
                        explanation="Context agent abstains when no finding_key anchor keys are supplied.",
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

            # 6. Anchor filtering
            if anchors is not None:
                evidence_list = [ev for ev in evidence_list if ev.finding_key in anchors]

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
