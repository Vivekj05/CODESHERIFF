"""Base protocol definition for LLM client."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel


class LLMClient(Protocol):
    """Protocol for LLM interactions."""

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
        temperature: float = 0.3,
        seed: int | None = None,
    ) -> str:
        """Generate text / JSON response from LLM given prompts and schema."""
        ...
