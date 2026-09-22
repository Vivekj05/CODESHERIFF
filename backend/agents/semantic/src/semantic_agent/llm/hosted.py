"""The Gemini client.

Two things changed after pointing a real key at the API (D-065).

**Transient failures are retried.** The free tier answers `503 high demand` often enough that a
single attempt loses samples routinely, and `gemini-3.5-flash` in particular was unusable without
this. Retries are bounded, backed off with jitter, and only for statuses that can succeed on a
second try — a 400 or a 404 is retried never, because the request is wrong and repeating it wastes
the quota the whole project is constrained by.

**A transport failure is not a model failure.** `ProviderUnavailableError` is raised so the
agent can abstain with `provider_unavailable` rather than `schema_violation`. The old code
reported three 503s as "failed to produce valid structured output", which blames the model for
something it was never asked, and would have been read as evidence about the model's reliability
when the ratios are fitted.
"""

from __future__ import annotations

import logging
import random
import time

import httpx
from pydantic import BaseModel

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"

RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})
"""Statuses where the same request can succeed on a later attempt.

429 is rate limiting and 503 is capacity; both are the free tier working as designed. 400, 403 and
404 are absent on purpose: a malformed request, a bad key and a retired model name do not improve
with repetition, and `gemini-2.0-flash` returning 404 is a configuration error a human must fix."""


class ProviderUnavailableError(RuntimeError):
    """The API could not be reached, or kept failing transiently. Not the model's fault."""


class HostedLLMClient:
    """Google Gemini via `generateContent`, with bounded retries."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-3.5-flash",
        base_url: str | None = None,
        timeout_seconds: float = 60.0,
        max_attempts: int = 3,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = (base_url or DEFAULT_BASE_URL).rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.max_attempts = max(1, max_attempts)

    def _backoff(self, attempt: int) -> float:
        """Exponential, with jitter.

        Jitter because every unit in an audit fails at the same moment when the provider is busy,
        and a fixed schedule would have them all retry in lockstep and stay synchronised.
        """
        return min(8.0, 0.5 * (2.0**attempt)) * (0.5 + random.random())

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        schema: type[BaseModel],
        temperature: float = 0.3,
        seed: int | None = None,
    ) -> str:
        """One completion as raw JSON text.

        Raises `ProviderUnavailableError` if it cannot get one.
        """
        if not self.api_key:
            raise ProviderUnavailableError("no API key is configured for HostedLLMClient")

        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        payload: dict[str, object] = {
            "system_instruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"role": "user", "parts": [{"text": user_prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "responseMimeType": "application/json",
            },
        }
        if seed is not None:
            generation_config = payload["generationConfig"]
            assert isinstance(generation_config, dict)
            generation_config["seed"] = seed

        last_error = "no attempt was made"

        for attempt in range(self.max_attempts):
            try:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    response = client.post(
                        url, headers={"Content-Type": "application/json"}, json=payload
                    )
            except httpx.HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "Gemini request failed (attempt %s/%s): %s",
                    attempt + 1,
                    self.max_attempts,
                    last_error,
                )
            else:
                if response.status_code == 200:
                    return self._extract(response.json())

                last_error = f"HTTP {response.status_code}: {response.text[:200]}"
                if response.status_code not in RETRYABLE_STATUS:
                    # The key, the model name or the request is wrong. Repeating it spends quota
                    # to learn nothing.
                    raise ProviderUnavailableError(last_error)
                logger.warning(
                    "Gemini returned a retryable %s (attempt %s/%s)",
                    response.status_code,
                    attempt + 1,
                    self.max_attempts,
                )

            if attempt + 1 < self.max_attempts:
                time.sleep(self._backoff(attempt))

        raise ProviderUnavailableError(
            f"{self.max_attempts} attempts failed; last was {last_error}"
        )

    def _extract(self, data: dict[str, object]) -> str:
        """The candidate text, or a clear failure naming what the response looked like.

        A 200 with no candidate is a real case — a safety block returns one — and it is a provider
        outcome rather than a malformed answer, so it must not be counted as a schema violation.
        """
        try:
            candidates = data["candidates"]
            assert isinstance(candidates, list)
            content = candidates[0]["content"]
            return str(content["parts"][0]["text"])
        except (KeyError, IndexError, TypeError, AssertionError) as exc:
            reason = data.get("promptFeedback") or data.get("error") or "unrecognised shape"
            logger.error("Gemini returned no usable candidate: %s", reason)
            raise ProviderUnavailableError(
                f"no candidate text in response ({reason}): {exc}"
            ) from exc
