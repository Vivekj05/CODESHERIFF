"""Runtime configuration for the fusion engine.

**The numbers are not configuration.** They were, until Chapter 14: a prior, a threshold and
four ratio tables with environment-variable defaults, which meant any deployment could quietly
run on values nobody fitted. They now come from `calibration.json` — fitted on the calibration
split, with the corpus hash that produced them recorded inside — and the only thing that can be
configured is *which artifact*, through `CALIBRATION_PATH` (D-084).

What is left here is the loading, plus the two accessors `apps/api` needs. The API stamps the
prior and the threshold onto every audit it opens, because §6 requires each audit to record the
numbers it actually ran under, and it must be able to read them without importing a settings
object holding credentials it has no business loading.
"""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from codesheriff_engine.calibration.artifact import (
    CALIBRATION_PATH_ENV,
    CalibrationArtifact,
    CalibrationError,
    active_artifact,
    artifact_path,
)
from codesheriff_engine.fusion.ratios import LR_MAX, LR_MIN, WitnessRatios

__all__ = [
    "CALIBRATION_PATH_ENV",
    "LR_MAX",
    "LR_MIN",
    "CalibrationArtifact",
    "CalibrationError",
    "EngineConfig",
    "WitnessRatios",
    "active_artifact",
    "artifact_path",
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

    And no prior, threshold or ratio fields. An operator who could raise the alert threshold
    from an environment variable could make a calibrated system uncalibrated without changing
    a line of code or leaving a trace on the audit — and every audit records a calibration run
    id precisely so that what it ran under is knowable afterwards.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    calibration_path: str = Field(default="")
    """Overrides the packaged artifact, from `CALIBRATION_PATH` (the field name, matched
    case-insensitively by pydantic-settings). Empty means the one shipped in the package.

    Read by `calibration.artifact.artifact_path` straight from the environment rather than
    from here, so that a process which never builds an `EngineConfig` — the CLI, a test —
    still resolves the same artifact. This field exists so the setting is *documented* in the
    settings object and `extra="ignore"` does not silently swallow it."""

    @classmethod
    def load(cls) -> EngineConfig:
        """Load configuration from environment with defaults."""
        return cls()

    # -- the fitted numbers, read through one door ---------------------------------------

    @property
    def artifact(self) -> CalibrationArtifact:
        return active_artifact()

    @property
    def prior_probability(self) -> float:
        return self.artifact.base_rate

    @property
    def alert_threshold(self) -> float:
        return self.artifact.alert_threshold

    @property
    def ratios(self) -> Mapping[str, WitnessRatios]:
        return self.artifact.table()
