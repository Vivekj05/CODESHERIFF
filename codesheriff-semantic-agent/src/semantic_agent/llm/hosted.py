"""Hosted LLM client for live API calls (OpenAI/Anthropic/LiteLLM)."""

from __future__ import annotations

import json
import logging
from typing import Optional, Type
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class HostedLLMClient:
    """Hosted LLM client communicating with API endpoints using JSON schema formatting."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gpt-4o-mini",
        base_url: str = "https://api.openai.com/v1",
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: Type[BaseModel],
        temperature: float = 0.3,
        seed: Optional[int] = None,
    ) -> str:
        """Call hosted LLM API and return raw response string."""
        if not self.api_key:
            raise RuntimeError("API key is not configured for HostedLLMClient")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "response_format": {"type": "json_object"},
        }
        if seed is not None:
            payload["seed"] = seed

        url = f"{self.base_url}/chat/completions"
        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return str(content)
