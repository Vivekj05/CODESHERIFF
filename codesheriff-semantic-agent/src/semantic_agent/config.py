"""Configuration settings for CodeSheriff Semantic Agent."""

from __future__ import annotations

import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class SemanticConfig(BaseSettings):
    """Configuration options for the Semantic Agent."""

    model_config = SettingsConfigDict(
        env_prefix="LLM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    agent_id: str = Field(default="semantic.hosted")
    agent_version: str = Field(default="0.1.0")
    model: str = Field(default="gpt-4o-mini")
    temperature: float = Field(default=0.3)
    n_samples: int = Field(default=3)
    budget_usd_per_unit: float = Field(default=0.05)
    api_key: str | None = Field(default=None)
    cache_path: str = Field(default=".cache/llm_cache.db")
    enable_cache: bool = Field(default=True)

    @classmethod
    def load(cls) -> SemanticConfig:
        """Load configuration from environment variables or defaults."""
        api_key = os.getenv("OPENAI_API_KEY") or os.getenv("LLM_API_KEY")
        cfg = cls()
        if api_key and not cfg.api_key:
            cfg.api_key = api_key
        return cfg
