"""Configuration management for CodeSheriff Fusion Engine."""

from __future__ import annotations

import os
from typing import Dict, Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_LIKELIHOOD_TABLE: Dict[str, Dict[str, float]] = {
    "structural.taint": {
        "high": 8.5,    # score >= 0.8
        "medium": 3.2,  # score >= 0.5
        "low": 0.8,     # score < 0.5
    },
    "structural.semgrep": {
        "high": 7.0,
        "medium": 3.0,
        "low": 0.9,
    },
    "semantic.hosted": {
        "high": 12.0,   # score >= 0.8 (high consensus)
        "medium": 4.5,  # score >= 0.5
        "low": 0.5,     # score < 0.5
    },
    "semantic.lora": {
        "high": 11.0,
        "medium": 4.0,
        "low": 0.6,
    },
    "context.rag": {
        "high": 4.2,    # score >= 0.8 (direct bypass of historical control)
        "medium": 2.1,  # score >= 0.5
        "low": 0.9,     # score < 0.5
    },
}

FALLBACK_LIKELIHOOD_TIER: Dict[str, float] = {
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
    prior_probability: float = Field(default=0.05, ge=0.001, le=0.999)
    alert_threshold: float = Field(default=0.70, ge=0.0, le=1.0)
    conflict_threshold: float = Field(default=0.50, ge=0.0, le=1.0)
    likelihood_table: Dict[str, Dict[str, float]] = Field(default_factory=lambda: DEFAULT_LIKELIHOOD_TABLE)

    # Multi-Agent Debate Configuration
    enable_debate: bool = True
    llm_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    debate_model: str = "gpt-4o-mini"
    debate_timeout_seconds: float = 15.0

    # GitHub Webhook & API Integration
    github_token: Optional[str] = Field(default=None, alias="GITHUB_TOKEN")
    github_webhook_secret: Optional[str] = Field(default=None, alias="GITHUB_WEBHOOK_SECRET")
    github_api_base: str = "https://api.github.com"

    # Server Settings
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False

    @classmethod
    def load(cls) -> EngineConfig:
        """Load configuration from environment with defaults."""
        return cls()
