"""Configuration settings for static_agent."""

from pathlib import Path
from typing import Final

from pydantic import BaseModel, Field

SEMGREP_VERSION: Final = "1.176.1"
"""The Semgrep build the structural ratios were fitted with. The corpus-run image pins the same
version; a different build is a different backend, whatever its rules say (D-104)."""

SEMGREP_RULESETS: Final[dict[str, str]] = {
    "security-audit.yml": "b109a039df712f30c6d3e25e1e8358053fd0f1c91b92d0e8d2871cd141fe602f",
    "owasp-top-ten.yml": "a59add95f4e0346fe98d334f363484e3fa343889d0624174f1e99de828eb17b4",
}
"""Each pinned ruleset and its SHA-256 (D-104).

The rules are fetched once, by a person, from Semgrep's registry (`p/security-audit`,
`p/owasp-top-ten`) into `.semgrep/rules/`, which is gitignored: they are Semgrep's to distribute,
not ours. Asking for `p/...` at analysis time instead fetched whatever the registry served that
day, so the structural witness changed under its fitted ratios with no record that it had. A
mismatched digest is an abstention, never a warning — editing this table is a re-fit.
"""


def _default_rules_dir() -> Path:
    # CWD-relative on purpose, like the runtime agent's `.wasm-runtimes/`: the worker and the
    # corpus run both start in the repository root, and in the corpus-run container that root is
    # the bind-mounted checkout, so both read the very same files.
    return Path.cwd() / ".semgrep" / "rules"


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
    semgrep_rules_dir: Path = Field(default_factory=_default_rules_dir)
    semgrep_rulesets: dict[str, str] = Field(default_factory=lambda: dict(SEMGREP_RULESETS))
    max_evidence_per_unit: int = 10
