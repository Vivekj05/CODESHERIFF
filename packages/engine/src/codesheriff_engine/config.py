"""Configuration management for CodeSheriff Fusion Engine."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_LIKELIHOOD_TABLE: dict[str, dict[str, float]] = {
    "structural.taint": {
        "high": 8.5,  # score >= 0.8
        "medium": 3.2,  # score >= 0.5
        "low": 0.8,  # score < 0.5
    },
    "structural.semgrep": {
        "high": 7.0,
        "medium": 3.0,
        "low": 0.9,
    },
    "semantic.hosted": {
        "high": 12.0,  # score >= 0.8 (high consensus)
        "medium": 4.5,  # score >= 0.5
        "low": 0.5,  # score < 0.5
    },
    "semantic.lora": {
        "high": 11.0,
        "medium": 4.0,
        "low": 0.6,
    },
    "context.rag": {
        "high": 4.2,  # score >= 0.8 (direct bypass of historical control)
        "medium": 2.1,  # score >= 0.5
        "low": 0.9,  # score < 0.5
    },
}

PROVISIONAL_PRIOR = 0.05
"""Asserted, not fitted. A placeholder until a corpus exists (PLAN.md Chapter 7 and Chapter 14).

A module constant rather than only a field default because `apps/api` has to stamp it onto every
audit it opens, and §6 requires each audit to record the numbers it actually ran under. Importing
one named constant keeps the edge out of the engine's configuration object, which also holds LLM
credentials the API process must never hold."""

PROVISIONAL_ALERT_THRESHOLD = 0.70
"""Asserted, not fitted. §6 requires the threshold to be selected on the validation split, which
does not exist yet. Nothing derived from this value may be presented as calibrated."""

FALLBACK_LIKELIHOOD_TIER: dict[str, float] = {
    "high": 3.0,
    "medium": 1.5,
    "low": 1.0,
}


class EngineConfig(BaseSettings):
    """Runtime configuration for Bayesian Fusion & Multi-Agent Engine."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Bayesian Math Parameters
    prior_probability: float = Field(default=PROVISIONAL_PRIOR, ge=0.001, le=0.999)
    alert_threshold: float = Field(default=PROVISIONAL_ALERT_THRESHOLD, ge=0.0, le=1.0)
    conflict_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    likelihood_table: dict[str, dict[str, float]] = Field(
        default_factory=lambda: DEFAULT_LIKELIHOOD_TABLE
    )

    # Multi-Agent Debate Configuration
    enable_debate: bool = True
    llm_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    anthropic_api_key: str | None = Field(default=None, alias="ANTHROPIC_API_KEY")
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    debate_model: str = "gpt-4o-mini"
    debate_timeout_seconds: float = 15.0

    # No GitHub settings, and no server settings. Until Chapter 6 this object carried
    # `github_token`, `github_webhook_secret`, `github_api_base`, `host` and `port` — and
    # `github_webhook_secret` was the one AUDIT.md 0.1 named: defined here, read nowhere, while the
    # endpoint it was meant to protect accepted anything. The webhook secret now lives in
    # `ApiConfig`, where the code that verifies signatures reads it, and the App credentials live
    # in `WorkerConfig`, where the code that mints tokens reads it. A credential nothing in the
    # package can use is not configuration; it is a claim that something is protected.

    @classmethod
    def load(cls) -> EngineConfig:
        """Load configuration from environment with defaults."""
        return cls()
