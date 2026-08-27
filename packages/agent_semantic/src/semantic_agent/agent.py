"""Main SemanticAgent analyzer implementation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import List, Optional, Set
from jinja2 import Template
from pydantic import ValidationError

from semantic_agent.config import SemanticConfig
from semantic_agent.consistency import aggregate_self_consistency
from semantic_agent.contracts import ChangeUnit, Evidence
from semantic_agent.llm.base import LLMClient
from semantic_agent.llm.budget import BudgetTracker
from semantic_agent.llm.cache import LLMCache
from semantic_agent.llm.hosted import HostedLLMClient
from semantic_agent.llm.stub import StubLLMClient
from semantic_agent.mapping import HallucinationGate
from semantic_agent.retrieval.base import Retriever
from semantic_agent.retrieval.null import NullRetriever
from semantic_agent.schema import LLMResponse

logger = logging.getLogger(__name__)


class SemanticAgent:
    """LLM-powered security analyzer agent for CodeSheriff."""

    def __init__(
        self,
        config: Optional[SemanticConfig] = None,
        llm_client: Optional[LLMClient] = None,
        retriever: Optional[Retriever] = None,
    ) -> None:
        self.config = config or SemanticConfig.load()
        self.agent_id = self.config.agent_id
        self.agent_version = self.config.agent_version

        if llm_client:
            self.llm_client = llm_client
        elif self.config.api_key:
            self.llm_client = HostedLLMClient(
                api_key=self.config.api_key,
                model=self.config.model,
            )
        else:
            self.llm_client = StubLLMClient()

        self.retriever = retriever or NullRetriever()
        self.cache = LLMCache(self.config.cache_path) if self.config.enable_cache else None
        self.budget_tracker = BudgetTracker(self.config.budget_usd_per_unit)

        self._prompts_dir = Path(__file__).parent / "prompts"
        self._system_prompt = self._load_system_prompt()
        self._user_template = self._load_user_template()

    def _load_system_prompt(self) -> str:
        p = self._prompts_dir / "system_v1.md"
        if p.exists():
            return p.read_text(encoding="utf-8")
        return "Perform security review and return findings matching LLMResponse JSON schema."

    def _load_user_template(self) -> Template:
        p = self._prompts_dir / "user_v1.jinja"
        if p.exists():
            return Template(p.read_text(encoding="utf-8"))
        return Template("Review unit: {{ unit.unit_id }}\n\n<code_to_analyze>\n{{ unit.post_src }}\n</code_to_analyze>")

    def analyze(
        self,
        unit: ChangeUnit,
        anchors: Optional[Set[str]] = None,
    ) -> List[Evidence]:
        """Analyze a ChangeUnit for security flaws. Guarantees zero unhandled exceptions."""
        try:
            # 1. Budget check
            if self.budget_tracker.is_exceeded():
                return [
                    Evidence.abstention(
                        agent_id=self.agent_id,
                        agent_version=self.agent_version,
                        unit_id=unit.unit_id,
                        reason="budget_exceeded",
                        explanation="Unit USD budget ceiling exceeded prior to analysis.",
                    )
                ]

            # 2. Context retrieval
            context = self.retriever.retrieve(unit)

            # 3. Prompt rendering
            user_prompt = self._user_template.render(unit=unit, context=context)

            # 4. Self-consistency sampling (n samples)
            n_samples = max(1, self.config.n_samples)
            valid_responses: List[LLMResponse] = []
            parse_failures = 0

            for i in range(n_samples):
                seed = 100 + i
                raw_response: Optional[str] = None

                # Check Cache
                cache_key = None
                if self.cache:
                    cache_key = self.cache.compute_key(
                        system_prompt=self._system_prompt,
                        user_prompt=user_prompt,
                        model=self.config.model,
                        agent_version=self.agent_version,
                        temperature=self.config.temperature,
                        seed=seed,
                    )
                    raw_response = self.cache.get(cache_key)

                # Generate if cache miss
                if not raw_response:
                    # Check pre-call budget
                    est_cost = self.budget_tracker.estimate_cost(
                        prompt_tokens=len(user_prompt) // 4,
                        completion_tokens=300,
                        model=self.config.model,
                    )
                    if not self.budget_tracker.check_budget(est_cost):
                        logger.warning("Budget limit reached during sampling")
                        break

                    try:
                        raw_response = self.llm_client.generate(
                            system_prompt=self._system_prompt,
                            user_prompt=user_prompt,
                            schema=LLMResponse,
                            temperature=self.config.temperature,
                            seed=seed,
                        )
                        self.budget_tracker.record_expenditure(est_cost)
                        if self.cache and cache_key and raw_response:
                            self.cache.set(cache_key, raw_response)
                    except Exception as gen_err:
                        logger.warning(f"LLM generation call failed: {gen_err}")
                        parse_failures += 1
                        continue

                # Parse JSON & Pydantic validation
                try:
                    data = json.loads(raw_response)
                    parsed_resp = LLMResponse.model_validate(data)

                    # Hallucination Gate filtering
                    filtered_findings = []
                    for f in parsed_resp.findings:
                        is_valid, reason = HallucinationGate.validate(f, unit)
                        if is_valid:
                            filtered_findings.append(f)
                        else:
                            logger.info(f"Hallucination gate rejected finding '{f.title}': {reason}")

                    valid_responses.append(LLMResponse(findings=filtered_findings))
                except (json.JSONDecodeError, ValidationError) as parse_err:
                    logger.warning(f"Failed to parse LLM response sample {i}: {parse_err}")
                    parse_failures += 1

            # 5. Handle complete schema failure
            if not valid_responses and parse_failures >= n_samples:
                return [
                    Evidence.abstention(
                        agent_id=self.agent_id,
                        agent_version=self.agent_version,
                        unit_id=unit.unit_id,
                        reason="schema_violation",
                        explanation="Failed to produce valid structured LLM output matching schema.",
                    )
                ]

            # 6. Aggregate self-consistency clusters
            evidence_list = aggregate_self_consistency(
                sample_responses=valid_responses,
                unit=unit,
                agent_id=self.agent_id,
                agent_version=self.agent_version,
            )

            # 7. Anchor filtering (if anchors supplied)
            if anchors is not None:
                evidence_list = [ev for ev in evidence_list if ev.finding_key in anchors]

            return evidence_list

        except Exception as e:
            logger.exception("Unhandled runtime exception in SemanticAgent")
            return [
                Evidence.abstention(
                    agent_id=self.agent_id,
                    agent_version=self.agent_version,
                    unit_id=unit.unit_id,
                    reason="runtime_error",
                    explanation=f"Unhandled exception during semantic analysis: {e}",
                )
            ]
