"""Configuration settings for static_agent."""

from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


class StaticConfig(BaseModel):
    """Static Agent configuration."""
    timeout_seconds: int = 30
    rules_dir: Path = Field(default_factory=lambda: Path("rules"))
    semgrep_binary: str = "semgrep"
    semgrep_timeout: int = 30
    semgrep_configs: list[str] = Field(
        default_factory=lambda: ["p/security-audit", "p/owasp-top-ten"]
    )
    max_evidence_per_unit: int = 10
