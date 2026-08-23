"""Patch & Verifier Agent Configuration Module."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class PatchVerifierConfig(BaseSettings):
    """Configuration settings for Patch Generator and Verifier Agent."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    llm_provider: str = "stub"  # 'stub' or 'hosted'
    llm_model: str = "gpt-4o"
    llm_temperature: float = 0.1
    max_tokens: int = 1000
    verification_threshold: float = 0.70
