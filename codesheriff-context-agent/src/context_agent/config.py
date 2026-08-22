"""Configuration settings for CodeSheriff Context Agent."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ContextConfig(BaseSettings):
    """Configuration settings for Context Agent and RAG storage."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    agent_id: str = Field(default="context.rag")
    agent_version: str = Field(default="0.1.0")
    chroma_db_dir: str = Field(default="./.chroma_db")
    embedding_model: str = Field(default="BAAI/bge-small-en-v1.5")
    similarity_threshold: float = Field(default=0.2)
    top_k: int = Field(default=3)

    @classmethod
    def load(cls) -> ContextConfig:
        """Load configuration settings."""
        return cls()
