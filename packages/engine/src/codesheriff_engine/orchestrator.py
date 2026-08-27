"""Multi-Agent Parallel Orchestrator for CodeSheriff."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, List, Optional, Set

from codesheriff_engine.config import EngineConfig
from codesheriff_engine.contracts import ChangeUnit, Evidence
from codesheriff_engine.fusion.bayes import FusionResult, fuse_all_evidence
from codesheriff_engine.fusion.debate import resolve_agent_conflict

logger = logging.getLogger(__name__)


class DummyAgent:
    """Fallback agent used when an analyzer package is not installed."""

    def __init__(self, agent_id: str, version: str = "0.0.0", reason: str = "agent_unloaded") -> None:
        self.id = agent_id
        self.version = version
        self.reason = reason

    def analyze(self, unit: ChangeUnit, anchors: Optional[Set[str]] = None) -> List[Evidence]:
        return [
            Evidence.abstention(
                agent_id=self.id,
                agent_version=self.version,
                unit_id=unit.unit_id,
                reason=self.reason,
                explanation=f"Agent '{self.id}' is not loaded or unavailable in this environment.",
            )
        ]


def _try_load_static_agent() -> Any:
    try:
        from static_agent.agent import StaticAgent
        return StaticAgent()
    except Exception as e:
        logger.info("Static agent not loaded: %s", e)
        return DummyAgent(agent_id="structural.taint", reason="agent_not_found")


def _try_load_semantic_agent() -> Any:
    try:
        from semantic_agent.agent import SemanticAgent
        return SemanticAgent()
    except Exception as e:
        logger.info("Semantic agent not loaded: %s", e)
        return DummyAgent(agent_id="semantic.hosted", reason="agent_not_found")


def _try_load_context_agent() -> Any:
    try:
        from context_agent.agent import ContextAgent
        return ContextAgent()
    except Exception as e:
        logger.info("Context agent not loaded: %s", e)
        return DummyAgent(agent_id="context.rag", reason="agent_not_found")


class Orchestrator:
    """Coordinates Phase 1 (Static AST/Taint) and Phase 2 (Parallel Semantic & Context) analysis."""

    def __init__(
        self,
        config: Optional[EngineConfig] = None,
        static_agent: Optional[Any] = None,
        semantic_agent: Optional[Any] = None,
        context_agent: Optional[Any] = None,
    ) -> None:
        self.config = config or EngineConfig.load()
        self.static_agent = static_agent if static_agent is not None else _try_load_static_agent()
        self.semantic_agent = semantic_agent if semantic_agent is not None else _try_load_semantic_agent()
        self.context_agent = context_agent if context_agent is not None else _try_load_context_agent()

    async def _run_agent_safe(
        self,
        agent: Any,
        unit: ChangeUnit,
        anchors: Optional[Set[str]] = None,
    ) -> List[Evidence]:
        """Execute an agent synchronously in a thread pool with exception isolation."""
        try:
            return await asyncio.to_thread(agent.analyze, unit, anchors)
        except Exception as e:
            agent_id = getattr(agent, "id", "unknown.agent")
            version = getattr(agent, "version", "0.0.0")
            logger.error("Agent '%s' failed unexpectedly: %s", agent_id, e)
            return [
                Evidence.abstention(
                    agent_id=agent_id,
                    agent_version=version,
                    unit_id=unit.unit_id,
                    reason="orchestrator_caught_exception",
                    explanation=f"Exception raised during execution: {str(e)}",
                )
            ]

    async def analyze_change_unit(
        self,
        unit: ChangeUnit,
        run_debate: bool = True,
    ) -> List[FusionResult]:
        """Execute two-phase multi-agent security analysis and Bayesian fusion over a ChangeUnit."""
        # -------------------------------------------------------------
        # Phase 1: Static Agent runs first to detect primary taint paths
        # -------------------------------------------------------------
        static_evidence = await self._run_agent_safe(self.static_agent, unit, anchors=None)

        # Collect positive finding keys to serve as anchors for Context & Semantic agents
        anchor_keys: Set[str] = {
            ev.finding_key
            for ev in static_evidence
            if not ev.abstained and not ev.finding_key.startswith("abstain:")
        }

        # -------------------------------------------------------------
        # Phase 2: Parallel execution of Semantic Agent & Context Agent
        # -------------------------------------------------------------
        semantic_task = self._run_agent_safe(self.semantic_agent, unit, anchor_keys)
        context_task = self._run_agent_safe(self.context_agent, unit, anchor_keys)

        semantic_evidence, context_evidence = await asyncio.gather(semantic_task, context_task)

        # -------------------------------------------------------------
        # Phase 3: Bayesian Odds Fusion
        # -------------------------------------------------------------
        all_evidence: List[Evidence] = static_evidence + semantic_evidence + context_evidence

        fusion_results = fuse_all_evidence(
            evidence_list=all_evidence,
            prior_p=self.config.prior_probability,
            alert_threshold=self.config.alert_threshold,
            likelihood_table=self.config.likelihood_table,
        )

        # Attach file information to fusion results
        for res in fusion_results:
            if not res.file:
                res.file = unit.file

        # -------------------------------------------------------------
        # Phase 4: Multi-Agent Debate for severe score conflicts
        # -------------------------------------------------------------
        if run_debate and self.config.enable_debate:
            resolved_results: List[FusionResult] = []
            for res in fusion_results:
                resolved = resolve_agent_conflict(
                    fusion=res,
                    code_snippet=unit.post_src,
                    config=self.config,
                )
                resolved_results.append(resolved)
            fusion_results = resolved_results

        return fusion_results

    async def analyze_change_units(
        self,
        units: List[ChangeUnit],
        run_debate: bool = True,
    ) -> List[FusionResult]:
        """Analyze a list of ChangeUnits across multiple files in a PR."""
        all_results: List[FusionResult] = []
        for unit in units:
            unit_results = await self.analyze_change_unit(unit, run_debate=run_debate)
            all_results.extend(unit_results)

        # Sort all findings by posterior probability descending
        all_results.sort(key=lambda r: r.posterior_probability, reverse=True)
        return all_results
