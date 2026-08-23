"""Configuration settings for static_agent."""

from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


def _default_rules_dir() -> Path:
    # 1. Package relative: <codesheriff-static-agent>/rules
    pkg_rules = Path(__file__).resolve().parent.parent.parent / "rules"
    if pkg_rules.exists():
        return pkg_rules
    # 2. Workspace relative
    ws_rules = Path("codesheriff-static-agent") / "rules"
    if ws_rules.exists():
        return ws_rules
    return Path("rules")


class StaticConfig(BaseModel):
    """Static Agent configuration."""
    timeout_seconds: int = 30
    rules_dir: Path = Field(default_factory=_default_rules_dir)
    semgrep_binary: str = "semgrep"
    semgrep_timeout: int = 30
    semgrep_configs: list[str] = Field(
        default_factory=lambda: ["p/security-audit", "p/owasp-top-ten"]
    )
    max_evidence_per_unit: int = 10

