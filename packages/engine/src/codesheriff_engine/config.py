"""Runtime configuration for the fusion engine.

The numbers themselves live in `codesheriff_engine.fusion.ratios`, which this module
re-exports for the two callers outside the engine that need them. `apps/api` stamps the
prior and the threshold onto every audit it opens, because §6 requires each audit to record
the numbers it actually ran under, and it must be able to import them without importing a
settings object that would make it load configuration it has no business holding.
"""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from codesheriff_engine.fusion.ratios import (
    FALLBACK_RATIOS,
    LR_MAX,
    LR_MIN,
    PROVISIONAL_ALERT_THRESHOLD,
    PROVISIONAL_PRIOR,
    PROVISIONAL_RATIOS,
    WitnessRatios,
)

__all__ = [
    "FALLBACK_RATIOS",
    "LR_MAX",
    "LR_MIN",
    "PROVISIONAL_ALERT_THRESHOLD",
    "PROVISIONAL_PRIOR",
    "PROVISIONAL_RATIOS",
    "EngineConfig",
    "WitnessRatios",
]


class EngineConfig(BaseSettings):
    """Runtime configuration for fusion.

    No LLM credentials, and no debate settings. Both left with `fusion/debate.py`, which
    Chapter 9 deleted rather than ported: it overwrote the fused posterior with a magic
    constant (`AUDIT.md` 2.2), and its default path was substring matching in which
    `"int("` — a substring of `print(` — counted as a sanitizer (`AUDIT.md` 2.3, D-009).

    No GitHub settings and no server settings either. The webhook secret lives in
    `ApiConfig` where signatures are verified, and the App credentials in `WorkerConfig`
    where installation tokens are minted. A credential nothing in the package can use is
    not configuration; it is a claim that something is protected.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    prior_probability: float = Field(default=PROVISIONAL_PRIOR, ge=0.001, le=0.999)
    alert_threshold: float = Field(default=PROVISIONAL_ALERT_THRESHOLD, ge=0.0, le=1.0)
    ratios: dict[str, WitnessRatios] = Field(default_factory=lambda: dict(PROVISIONAL_RATIOS))

    @classmethod
    def load(cls) -> EngineConfig:
        """Load configuration from environment with defaults."""
        return cls()
