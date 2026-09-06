"""Configuration settings for static_agent."""

from pathlib import Path

from pydantic import BaseModel, Field


class StaticConfig(BaseModel):
    """Static Agent configuration."""

    timeout_seconds: int = 30
    # Package-relative, not CWD-relative. A bare Path("rules") resolved against
    # whatever directory pytest happened to start in, so the catalog silently
    # loaded empty when run from the workspace root — and an agent with no rules
    # reports no findings while looking exactly like an agent that found none.
    rules_dir: Path = Field(default_factory=lambda: Path(__file__).parent / "rules")
    semgrep_binary: str = "semgrep"
    semgrep_timeout: int = 30
    semgrep_configs: list[str] = Field(
        default_factory=lambda: ["p/security-audit", "p/owasp-top-ten"]
    )
    max_evidence_per_unit: int = 10
