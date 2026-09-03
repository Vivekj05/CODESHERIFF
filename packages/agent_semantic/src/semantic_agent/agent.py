"""The semantic witness: absorbed model knowledge, bounded by a hallucination gate.

Its basis for a decision is intent — what the code is trying to do, where trust ends, which
invariant is missing — which is why it is the only witness that can see an authorisation bug. Its
failure mode is being confidently wrong, or agreeable, and everything defensive in this module
exists to bound that.

Four things changed in Chapter 11:

**The untrusted region is delimited by a per-request random sentinel** (`AUDIT.md` 0.3). The old
template interpolated `post_src` between literal `<code_to_analyze>` tags, so code containing that
closing tag ended the data region and everything after it read as instruction. A sentinel the code
author cannot predict cannot be forged.

**The exemplars are loaded** (`AUDIT.md` 3.9). Three worked examples, two of which correctly report
nothing — the mechanism that makes `{"findings": []}` a demonstrated answer rather than a permitted
one.

**An oversized unit abstains** (`AUDIT.md` 3.11, D-015). It used to trip the budget check, `break`,
and fall through to an empty list, which downstream is indistinguishable from "reviewed, clean".

**A provider failure is not a model failure** (D-065). Three 503s used to surface as
`schema_violation`, blaming the model for output it was never asked for — and that misattribution
would have been read as evidence about the model when the likelihood ratios are fitted.
"""

from __future__ import annotations

import json
import logging
import secrets
from pathlib import Path

from jinja2 import Template
from pydantic import ValidationError

from codesheriff_contracts import IN_SCOPE_CWES, ChangeUnit, Evidence
from semantic_agent.config import AGENT_ID, AGENT_VERSION, SemanticConfig
from semantic_agent.consistency import aggregate_self_consistency
from semantic_agent.exemplars import load_exemplars, render_exemplars
from semantic_agent.llm.base import LLMClient
from semantic_agent.llm.budget import BudgetTracker
from semantic_agent.llm.cache import LLMCache
from semantic_agent.llm.hosted import HostedLLMClient, ProviderUnavailableError
from semantic_agent.mapping import HallucinationGate
from semantic_agent.retrieval.base import Retriever
from semantic_agent.retrieval.null import NullRetriever
from semantic_agent.schema import LLMResponse

logger = logging.getLogger(__name__)

MAX_UNIT_BYTES = 60_000
"""Above this the agent abstains rather than analysing (D-015, `AUDIT.md` 3.11).

Not a token limit — the models in use have far larger context windows. It is the point past which a
single function is no longer the thing this agent was designed to reason about, and a confident
answer over 60 kB of code is not one an intent analysis earned."""

CACHE_KEY_NONCE = "CODESHERIFF-CACHEKEY"
"""A fixed stand-in used only when computing the cache key.

The real sentinel is random per request, so keying the cache on the rendered prompt would make
every lookup a miss and turn the cache into a write-only table. Rendering a second time with a
constant makes the key mean "this prompt, modulo the sentinel" — which is exactly the equivalence
the cache wants, and it still changes when the template or the code does."""


class SemanticAgent:
    """LLM-backed security analyser. Never raises; abstains with a distinct reason instead."""

    def __init__(
        self,
        config: SemanticConfig | None = None,
        llm_client: LLMClient | None = None,
        retriever: Retriever | None = None,
    ) -> None:
        self.config = config or SemanticConfig.load()
        self.agent_id = AGENT_ID
        self.agent_version = AGENT_VERSION

        # A missing API key leaves this None and `analyze` abstains. It must never fall back to a
        # stub: a stub answers anything it does not recognise with `{"findings": []}`, which this
        # agent would report as SILENCE across all ten in-scope CWEs — a witness that had read
        # nothing arguing, below a likelihood ratio of 1.0, that the code is safe (D-057).
        self.llm_client: LLMClient | None
        if llm_client is not None:
            self.llm_client = llm_client
        elif self.config.api_key:
            self.llm_client = HostedLLMClient(api_key=self.config.api_key, model=self.config.model)
        else:
            logger.warning(
                "semantic.hosted has no API key and no injected client; it will abstain on every "
                "unit. Set GEMINI_API_KEY, or expect one fewer witness."
            )
            self.llm_client = None

        self.retriever = retriever or NullRetriever()
        self.cache = LLMCache(self.config.cache_path) if self.config.enable_cache else None
        self.budget_tracker = BudgetTracker(self.config.budget_usd_per_unit)

        self._prompts_dir = Path(__file__).parent / "prompts"
        self._system_prompt = self._load_system_prompt()
        self._user_template = self._load_user_template()
        self._exemplars = load_exemplars()

    # -- prompt assets --------------------------------------------------------------------------

    def _load_system_prompt(self) -> str:
        path = self._prompts_dir / "system_v1.md"
        if path.exists():
            return path.read_text(encoding="utf-8")
        logger.error("system_v1.md is missing; falling back to a minimal instruction")
        return "Perform a security review and return findings matching the LLMResponse schema."

    def _load_user_template(self) -> Template:
        # Annotated rather than returned directly: jinja2 types `Template.__new__` as
        # returning `Any`, and under `warn_return_any` returning it unannotated is an error.
        template: Template
        path = self._prompts_dir / "user_v1.jinja"
        if path.exists():
            template = Template(path.read_text(encoding="utf-8"))
            return template
        logger.error("user_v1.jinja is missing; falling back to a minimal template")
        template = Template(
            "Review unit {{ unit.unit_id }}\n\n"
            "BEGIN {{ nonce }}\n{{ unit.post_src }}\nEND {{ nonce }}"
        )
        return template

    def build_prompt(self, unit: ChangeUnit, context: object, nonce: str) -> str:
        """The user message: worked examples, then the unit, both inside the same sentinel."""
        examples = render_exemplars(self._exemplars, nonce)
        body = self._user_template.render(unit=unit, context=context, nonce=nonce)
        return f"{examples}\n{body}" if examples else body

    @staticmethod
    def new_nonce() -> str:
        """A sentinel the author of the code under analysis cannot predict.

        `secrets`, not `random`: this is the whole prompt-injection boundary, and a value drawn
        from a seeded or predictable generator could be reproduced by someone who can see enough
        output to infer the state."""
        return f"CODESHERIFF-{secrets.token_hex(8).upper()}"

    # -- abstention -----------------------------------------------------------------------------

    def _abstain(self, unit: ChangeUnit, reason: str, explanation: str) -> list[Evidence]:
        return [
            Evidence.abstention(
                agent_id=self.agent_id,
                agent_version=self.agent_version,
                unit_id=unit.unit_id,
                reason=reason,
                explanation=explanation,
            )
        ]

    # -- analysis -------------------------------------------------------------------------------

    def analyze(self, unit: ChangeUnit) -> list[Evidence]:
        """Analyse one ChangeUnit. Runs blind (D-008) and guarantees zero unhandled exceptions."""
        try:
            if self.llm_client is None:
                return self._abstain(
                    unit,
                    "llm_unavailable",
                    "No API key is configured and no client was supplied, so no model examined "
                    "this unit.",
                )

            unit_bytes = len(unit.post_src.encode("utf-8"))
            if unit_bytes > MAX_UNIT_BYTES:
                # Never truncate. A truncated unit produces confident findings from half-read
                # code, biased toward over-reporting, and silently invalidates calibration (D-015).
                return self._abstain(
                    unit,
                    "unit_too_large",
                    f"Unit is {unit_bytes} bytes, over the {MAX_UNIT_BYTES} byte limit; analysing "
                    "part of it would produce confident findings from half-read code.",
                )

            # The ceiling is per unit, so the count starts here. Without this the agent
            # analyses the first few units of an audit and abstains `budget_exceeded` on every
            # one after them — a per-process budget under a per-unit name.
            self.budget_tracker.reset()
            if self.budget_tracker.is_exceeded():
                return self._abstain(
                    unit, "budget_exceeded", "Unit USD budget ceiling exceeded before analysis."
                )

            nonce = self.new_nonce()
            context = self.retriever.retrieve(unit)
            user_prompt = self.build_prompt(unit, context, nonce)
            cache_prompt = self.build_prompt(unit, context, CACHE_KEY_NONCE)

            valid_responses, provider_failures, parse_failures = self._sample(
                unit, user_prompt, cache_prompt
            )

            # A provider that never answered is not a model that answered badly. Checked before
            # the schema case, because when the API is down every sample fails both ways and the
            # reason recorded has to be the one a human can act on (D-065).
            if not valid_responses and provider_failures:
                return self._abstain(
                    unit,
                    "provider_unavailable",
                    f"The model provider failed on {provider_failures} of "
                    f"{provider_failures + parse_failures} attempt(s).",
                )

            if not valid_responses and parse_failures:
                return self._abstain(
                    unit,
                    "schema_violation",
                    f"The model returned output that did not match the schema on all "
                    f"{parse_failures} attempt(s).",
                )

            # Zero samples, and neither the provider nor the schema is why: the budget stopped
            # the loop before the first call. That is an agent that did not look, and it must
            # abstain. Falling through to the SILENCE below would have it report "reviewed the
            # unit and found nothing" across all ten in-scope CWEs, at a likelihood ratio under
            # 1.0, having read nothing — the shape of `AUDIT.md` 3.12, reached by a different
            # road. Found by the Chapter 14 harness (D-088).
            if not valid_responses:
                return self._abstain(
                    unit,
                    "budget_exceeded",
                    f"The unit budget of ${self.config.budget_usd_per_unit:.4f} was reached "
                    f"before any sample completed; no model output was examined.",
                )

            evidence = aggregate_self_consistency(
                sample_responses=valid_responses,
                unit=unit,
                agent_id=self.agent_id,
                agent_version=self.agent_version,
            )
            if evidence:
                return evidence

            # Ran to completion with nothing to report: SILENCE, not an empty list. The model was
            # asked about the whole in-scope set, so its silence is informative about all of it
            # (D-005, D-006). Returning [] here would be indistinguishable from a failure.
            return [
                Evidence.silence(
                    agent_id=self.agent_id,
                    agent_version=self.agent_version,
                    unit_id=unit.unit_id,
                    covered_cwes=IN_SCOPE_CWES,
                    explanation="Reviewed the unit and reported no in-scope finding.",
                )
            ]

        except Exception as exc:  # never raises (CLAUDE.md, "Agents never raise")
            logger.exception("Unhandled exception in SemanticAgent on unit %s", unit.unit_id)
            return self._abstain(unit, "runtime_error", f"{type(exc).__name__}: {exc}")

    def _sample(
        self, unit: ChangeUnit, user_prompt: str, cache_prompt: str
    ) -> tuple[list[LLMResponse], int, int]:
        """n samples at varying seeds. Returns `(valid, provider_failures, parse_failures)`."""
        n_samples = max(1, self.config.n_samples)
        valid: list[LLMResponse] = []
        provider_failures = 0
        parse_failures = 0

        for index in range(n_samples):
            seed = 100 + index
            raw: str | None = None
            cache_key: str | None = None

            if self.cache:
                cache_key = self.cache.compute_key(
                    system_prompt=self._system_prompt,
                    user_prompt=cache_prompt,
                    model=self.config.model,
                    agent_version=self.agent_version,
                    temperature=self.config.temperature,
                    seed=seed,
                )
                raw = self.cache.get(cache_key)

            if not raw:
                estimated = self.budget_tracker.estimate_cost(
                    prompt_tokens=len(user_prompt) // 4,
                    completion_tokens=300,
                    model=self.config.model,
                )
                if not self.budget_tracker.check_budget(estimated):
                    logger.warning(
                        "Budget reached after %s of %s samples on unit %s",
                        index,
                        n_samples,
                        unit.unit_id,
                    )
                    break

                try:
                    raw = self.llm_client.generate(  # type: ignore[union-attr]
                        system_prompt=self._system_prompt,
                        user_prompt=user_prompt,
                        schema=LLMResponse,
                        temperature=self.config.temperature,
                        seed=seed,
                    )
                except ProviderUnavailableError as exc:
                    logger.warning("Provider unavailable on sample %s: %s", index, exc)
                    provider_failures += 1
                    continue
                except Exception as exc:
                    # An unexpected client error is still the provider's side of the boundary.
                    logger.warning("LLM client raised on sample %s: %s", index, exc)
                    provider_failures += 1
                    continue

                self.budget_tracker.record_expenditure(estimated)
                if self.cache and cache_key and raw:
                    self.cache.set(cache_key, raw)

            parsed = self._parse(raw, unit, index)
            if parsed is None:
                parse_failures += 1
            else:
                valid.append(parsed)

        return valid, provider_failures, parse_failures

    def _parse(self, raw: str, unit: ChangeUnit, index: int) -> LLMResponse | None:
        """Parse one sample and drop the findings the hallucination gate rejects.

        A rejected finding does not fail the sample. The model may report one real finding and one
        invention, and discarding the whole response would lose the real one — dropping the
        invention is what "drop, never relabel" means here (D-021).
        """
        try:
            parsed = LLMResponse.model_validate(json.loads(raw))
        except (json.JSONDecodeError, ValidationError) as exc:
            logger.warning("Sample %s did not match the schema: %s", index, exc)
            return None

        kept = []
        for finding in parsed.findings:
            ok, reason = HallucinationGate.validate(finding, unit)
            if ok:
                kept.append(finding)
            else:
                logger.info("Hallucination gate rejected %r: %s", finding.title, reason)
        return LLMResponse(findings=kept)
