"""Canonical vendored data contracts for CodeSheriff.

DO NOT EDIT LOCALLY.
All agent repositories vendor this file byte-for-byte.
Contract integrity is verified by SHA-256 in test_contract_integrity.py.
"""

from __future__ import annotations

import hashlib
from typing import Any, List, Optional
from pydantic import BaseModel, Field

CONTRACT_VERSION = "1.0.0"


class Artifact(BaseModel):
    """Structured attachment to an Evidence item (e.g. taint path, SARIF snippet)."""
    artifact_type: str
    content: Any


class ChangeUnit(BaseModel):
    """Input payload representing a changed symbol/function under review."""
    contract_version: str = CONTRACT_VERSION
    unit_id: str
    repo: str
    language: str
    file: str
    symbol: Optional[str] = None
    pre_src: str
    post_src: str
    changed_lines: List[int]
    start_line: int = 1
    neighbours: List[dict[str, Any]] = Field(default_factory=list)
    imports: List[str] = Field(default_factory=list)
    base_sha: str
    head_sha: str
    is_test_file: bool = False
    repo_path: Optional[str] = None


class Evidence(BaseModel):
    """Output evidence produced by an analyzer."""
    agent_id: str
    agent_version: str
    unit_id: str
    finding_key: str
    cwe: Optional[str] = None
    raw_score: float = 0.0
    confidence: float = 1.0
    explanation: str
    artifacts: List[Artifact] = Field(default_factory=list)
    abstained: bool = False
    abstain_reason: Optional[str] = None

    @classmethod
    def abstention(
        cls,
        agent_id: str,
        agent_version: str,
        unit_id: str,
        reason: str,
        explanation: str = "",
    ) -> Evidence:
        """Create an abstention Evidence instance."""
        return cls(
            agent_id=agent_id,
            agent_version=agent_version,
            unit_id=unit_id,
            finding_key=f"abstain:{unit_id}:{reason}",
            cwe=None,
            raw_score=0.0,
            confidence=0.0,
            explanation=explanation or f"Abstained due to: {reason}",
            artifacts=[],
            abstained=True,
            abstain_reason=reason,
        )


def finding_key(file: str, symbol: Optional[str], cwe: str, sink_expr: str) -> str:
    """Generate a stable, cross-agent identifier for a reported finding."""
    normalized = f"{file}:{symbol or ''}:{cwe.upper()}:{sink_expr.strip()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
