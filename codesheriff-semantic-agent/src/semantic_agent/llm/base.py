"""Base protocol definition for LLM client."""

from __future__ import annotations

from typing import Protocol, Type
from pydantic import BaseModel


class LLMClient(Protocol):
    """Protocol for LLM interactions."""

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: Type[BaseModel],
        temperature: float = 0.3,
        seed: int | None = None,
    ) -> str:
        """Generate text / JSON response from LLM given prompts and schema."""
        ...
