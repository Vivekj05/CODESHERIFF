"""Configuration for the semantic agent.

**The names here are the names in `.env.example`, and that is the whole point of this file.**

It used to carry `env_prefix="LLM_"`, so the settings loader looked for `LLM_MODEL`,
`LLM_TEMPERATURE` and `LLM_CACHE_PATH` while `.env.example` documented `SEMANTIC_MODEL`,
`SEMANTIC_TEMPERATURE` and `SEMANTIC_CACHE_PATH`. Every one of those was read by nothing.

Worse, `load()` reached for the API key with `os.getenv("GEMINI_API_KEY")`, which reads the
*process* environment — and `pydantic-settings` parses `.env` into the settings object without
exporting anything into `os.environ`. So `GEMINI_API_KEY=...` in a `.env` file, exactly as
`.env.example` instructs, produced `api_key=None` and an agent that abstained on every unit with
`llm_unavailable`. The abstention is honest (D-057), which is what made this hard to see: the
system reported that it could not run, and the reason it could not run was that the documented way
of configuring it did not work.

Explicit `alias` per field, no prefix — the same shape as `WorkerConfig` and `ApiConfig`. A
configuration key that the code does not read is not configuration; it is a claim.
"""

from __future__ import annotations

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

AGENT_ID = "semantic.hosted"
"""Fixed, and deliberately not configurable.

Fusion refuses an `agent_id` that maps to no witness (D-052), so an environment variable that could
change it is a way to make every audit raise. It is also the identity the calibrated likelihood
ratios are fitted against, and a witness that can be renamed by deployment is not one."""

AGENT_VERSION = "0.1.0"


class SemanticConfig(BaseSettings):
    """Everything the semantic agent needs. Nothing that identifies it."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    api_key: str | None = Field(
        default=None,
        validation_alias=AliasChoices("GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_API_KEY"),
    )
    """Unset means the agent ABSTAINS on every unit with `llm_unavailable` (D-057).

    It must never fall back to a stub: a stub answers anything it does not recognise with
    `{"findings": []}`, which this agent would report as SILENCE across all ten in-scope CWEs — a
    witness that had read nothing arguing, at a likelihood ratio below 1.0, that the code is safe
    (`AUDIT.md` 3.12)."""

    model: str = Field(default="gemini-3.1-flash-lite", alias="SEMANTIC_MODEL")
    """Pinned, never a `-latest` alias, and pinned to the model the fit was measured with.

    A floating alias can change the model between the run that fits the likelihood ratios and
    every run scored against them, which makes a calibration figure unreproducible (§6).

    This default is not a preference. Every recorded response in `calibration/responses/` was
    produced by `gemini-3.1-flash-lite`, and the `semantic.hosted` likelihood ratios in
    `calibration.json` describe *that* witness. A checkout whose default named a different
    model would record the held-out split under a witness the ratios were never fitted for,
    and the mismatch would be invisible — the run would succeed and the numbers would be wrong.
    Changing it means re-recording every split and re-fitting, not editing one line.

    Model names expire. `gemini-2.0-flash` was this default until the API began answering 404
    "no longer available", and `gemini-2.5-flash` is refused to keys created after it shipped —
    so a dead default is a live failure mode, not a hypothetical one."""
    temperature: float = Field(default=0.3, alias="SEMANTIC_TEMPERATURE")
    n_samples: int = Field(default=3, alias="SEMANTIC_N_SAMPLES")
    """Self-consistency samples per unit. The cost target in `CLAUDE.md` is stated at n=3."""

    budget_usd_per_unit: float = Field(default=0.01, alias="SEMANTIC_BUDGET_PER_UNIT")
    """Hard ceiling per ChangeUnit. Exceeding it abstains rather than truncating the analysis."""

    cache_path: str = Field(default=".cache/semantic_llm_cache.sqlite", alias="SEMANTIC_CACHE_PATH")
    enable_cache: bool = Field(default=True, alias="SEMANTIC_ENABLE_CACHE")

    @property
    def agent_id(self) -> str:
        return AGENT_ID

    @property
    def agent_version(self) -> str:
        return AGENT_VERSION

    @classmethod
    def load(cls) -> SemanticConfig:
        """Load from `.env` and the process environment, with the environment winning.

        No `os.getenv` fallback. The settings loader already reads both, and reaching past it was
        what made a documented `.env` key silently do nothing.
        """
        return cls()
