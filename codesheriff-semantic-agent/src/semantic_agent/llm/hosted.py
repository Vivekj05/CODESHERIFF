"""Hosted LLM client for Google Gemini API."""

from __future__ import annotations

import json
import logging
from typing import Optional, Type
import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class HostedLLMClient:
    """Google Gemini hosted LLM client using JSON schema formatting."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-1.5-flash",
        base_url: Optional[str] = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: Type[BaseModel],
        temperature: float = 0.3,
        seed: Optional[int] = None,
    ) -> str:
        """Call Gemini API and return raw response string formatted as JSON."""
        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY is not configured for HostedLLMClient")

        # Native Gemini generateContent API
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        headers = {"Content-Type": "application/json"}

        payload = {
            "system_instruction": {
                "parts": [{"text": system_prompt}]
            },
            "contents": [
                {
                    "role": "user",
                    "parts": [{"text": user_prompt}]
                }
            ],
            "generationConfig": {
                "temperature": temperature,
                "responseMimeType": "application/json",
            }
        }

        if seed is not None:
            payload["generationConfig"]["seed"] = seed

        with httpx.Client(timeout=30.0) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            
            try:
                content = data["candidates"][0]["content"]["parts"][0]["text"]
                return str(content)
            except (KeyError, IndexError) as err:
                logger.error(f"Unexpected response structure from Gemini API: {data}")
                raise RuntimeError(f"Failed to extract candidate text from Gemini response: {err}")
