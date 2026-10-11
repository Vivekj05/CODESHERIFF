"""The single shared CodeSheriff data contract.

Every agent, the engine, and the apps import this module. It is never vendored:
four byte-identical copies previously existed, kept in sync by a SHA-256 test whose
expected hash was rewritten to make it pass (AUDIT.md 4.8). Agent isolation is now
enforced by import-linter instead — see the root pyproject.toml.

Contract v2.0.0 implements PROJECT_CONTEXT.md §5 and closes AUDIT.md Tier 1.
Several choices here look odd and are load-bearing; each cites its decision.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_serializer, model_validator

CONTRACT_VERSION = "2.0.0"


# ---------------------------------------------------------------------------
# Scope. A closed set (PROJECT_CONTEXT.md §6).
#
# Closed means closed: a DETECTION carrying a CWE outside this set is a contract
# violation, not a curiosity. Agents drop out-of-scope findings before emitting.
# Widening the set invalidates every number fitted against it, so it changes only
# by an explicit decision recorded in DECISIONS.md.
# ---------------------------------------------------------------------------
IN_SCOPE_CWES: frozenset[str] = frozenset(
    {
        "CWE-22",  # Path traversal
        "CWE-78",  # OS command injection
        "CWE-79",  # Cross-site scripting
        "CWE-89",  # SQL injection
        "CWE-94",  # Code injection
        "CWE-502",  # Deserialisation of untrusted data
        "CWE-639",  # Authorisation bypass through user-controlled key
        "CWE-798",  # Hard-coded credentials
        "CWE-862",  # Missing authorisation
        "CWE-918",  # Server-side request forgery
    }
)


class EvidenceKind(StrEnum):
    """What an agent is actually saying. Three states, never two (D-005).

    The distinction that matters is between the second and the third. An agent that
    ran and found nothing is evidence of absence, and must be able to push a
    posterior down. An agent that could not run is evidence of nothing at all. A
    single `abstained: bool` conflates them, which lets an agent that could not look
    vote the code innocent.
    """

    DETECTION = "detection"
    """Ran, and found something. Carries a finding_key and an in-scope CWE."""

    SILENCE = "silence"
    """Ran to completion, found nothing. Carries covered_cwes; LR < 1.0."""

    ABSTENTION = "abstention"
    """Could not run, or could not run soundly. Carries a reason; LR exactly 1.0."""


def finding_key(file: str, qualified_symbol: str, cwe: str) -> str:
    """Stable cross-agent identifier for one finding.

    Deliberately EXCLUDES the sink expression (D-004). Including it was the single
    defect that disabled the entire thesis: the taint engine reports
    `cursor.execute(query)` and the LLM reports `cursor.execute`, so one bug produced
    two keys, every finding became a singleton, and the Bayesian engine never
    performed one update. Two witnesses must land on the same case number while
    describing what they saw in their own words.

    `qualified_symbol` must come from `ChangeUnit.qualified_symbol` — never
    reassembled at the call site, or agents drift apart again on the separator.
    """
    normalized = f"{file}::{qualified_symbol}::{cwe.strip().upper()}"
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


class Artifact(BaseModel):
    """Structured attachment to an Evidence item (taint path, SARIF match, ...)."""

    artifact_type: str
    content: Any


class PRContext(BaseModel):
    """Pull request prose. Deliberately NOT part of ChangeUnit (D-014).

    Attacker-controlled: a PR author writes the title and body, so this text can
    carry prompt injection and must never be mistaken for code under analysis.

    It is also absent from corpus cases. Embedding it in ChangeUnit would make a
    corpus run structurally different from a production run, and the corpus is what
    every calibrated number is fitted on.
    """

    number: int | None = None
    title: str = ""
    description: str = ""
    author: str | None = None


class ChangeUnit(BaseModel):
    """One changed function — the unit of analysis. Agents receive this and nothing else."""

    contract_version: str = CONTRACT_VERSION
    unit_id: str
    repo: str
    language: str
    file: str
    symbol: str | None = None

    enclosing_class: str | None = None
    """Set when the symbol is a method (D-013). Feeds `qualified_symbol`."""

    decorators: list[str] = Field(default_factory=list)
    """Decorators on the changed symbol, e.g. `@require_csrf_token` (D-013).

    Their removal is the entire signal for the access-control CWEs (862, 639),
    which no taint path can see.
    """

    pre_src: str | None = None
    """Source before the change. None for an added function — there is no before."""

    post_src: str
    changed_lines: list[int] = Field(default_factory=list)
    start_line: int = 1
    neighbours: list[dict[str, Any]] = Field(default_factory=list)
    imports: list[str] = Field(default_factory=list)
    base_sha: str
    head_sha: str
    is_test_file: bool = False
    repo_path: str | None = None

    @property
    def qualified_symbol(self) -> str:
        """The one canonical symbol name for keying. Never reassemble this by hand.

        Every agent keys through this property. Two agents formatting the
        qualification differently would reintroduce the D-004 bug by another route.
        """
        name = self.symbol or "<module>"
        return f"{self.enclosing_class}.{name}" if self.enclosing_class else name

    def key_for(self, cwe: str) -> str:
        """finding_key for this unit and a CWE. The only way agents should build keys."""
        return finding_key(self.file, self.qualified_symbol, cwe)


class Evidence(BaseModel):
    """One agent's statement about one ChangeUnit.

    Construct through `detection()`, `silence()` or `abstention()` rather than
    directly — the validator below rejects the states those constructors prevent.
    """

    agent_id: str
    agent_version: str
    unit_id: str
    kind: EvidenceKind

    finding_key: str | None = None
    """DETECTION only. None on SILENCE and ABSTENTION, which are statements about
    the whole unit rather than about one finding."""

    cwe: str | None = None
    """DETECTION only, and always within IN_SCOPE_CWES."""

    covered_cwes: frozenset[str] = frozenset()
    """SILENCE only: what this agent was actually capable of finding (D-006).

    Without it, the taint engine's silence on CWE-862 — for which it holds no rules
    whatsoever — suppresses every semantic-only authorisation finding. An agent's
    silence may only count against CWEs it can actually detect.
    """

    reason: str | None = None
    """ABSTENTION only: a distinct machine-readable cause, e.g. `unit_too_large`."""

    raw_score: float = 0.0
    confidence: float = 1.0
    explanation: str = ""
    artifacts: list[Artifact] = Field(default_factory=list)

    @field_serializer("covered_cwes")
    def _serialise_covered_cwes(self, value: frozenset[str]) -> list[str]:
        """Sorted list on the wire.

        A frozenset is not JSON-serialisable, and Evidence has to survive a round trip
        through the database, the API and the dashboard. Sorted rather than arbitrary
        order so serialised evidence is byte-stable — snapshots and content hashes
        depend on it.
        """
        return sorted(value)

    @model_validator(mode="after")
    def _check_kind_invariants(self) -> Evidence:
        if self.kind is EvidenceKind.DETECTION:
            if not self.finding_key:
                raise ValueError("DETECTION requires a finding_key")
            if not self.cwe:
                raise ValueError("DETECTION requires a cwe")
            if self.cwe.strip().upper() not in IN_SCOPE_CWES:
                raise ValueError(
                    f"DETECTION cwe {self.cwe!r} is outside IN_SCOPE_CWES; agents must "
                    "drop out-of-scope findings before emitting"
                )
            if self.covered_cwes:
                raise ValueError("covered_cwes belongs to SILENCE, not DETECTION")
        else:
            if self.finding_key is not None:
                raise ValueError(
                    f"{self.kind.value} is a statement about the unit and carries no "
                    "finding_key; raw string keys such as 'abstain:<unit_id>' are the "
                    "AUDIT.md 1.1 bypass and are not permitted"
                )
            if self.cwe is not None:
                raise ValueError(f"{self.kind.value} carries no cwe")

        if self.kind is EvidenceKind.SILENCE:
            if not self.covered_cwes:
                raise ValueError(
                    "SILENCE requires covered_cwes: silence about CWEs an agent cannot "
                    "detect is not evidence (D-006)"
                )
            unknown = {c.strip().upper() for c in self.covered_cwes} - IN_SCOPE_CWES
            if unknown:
                raise ValueError(f"covered_cwes outside IN_SCOPE_CWES: {sorted(unknown)}")

        if self.kind is EvidenceKind.ABSTENTION and not self.reason:
            raise ValueError("ABSTENTION requires a reason")
        if self.kind is not EvidenceKind.ABSTENTION and self.reason is not None:
            raise ValueError("reason belongs to ABSTENTION only")

        return self

    # -- constructors -------------------------------------------------------

    @classmethod
    def detection(
        cls,
        agent_id: str,
        agent_version: str,
        unit_id: str,
        finding_key: str,
        cwe: str,
        raw_score: float,
        confidence: float = 1.0,
        explanation: str = "",
        artifacts: list[Artifact] | None = None,
    ) -> Evidence:
        """Ran, and found something."""
        return cls(
            agent_id=agent_id,
            agent_version=agent_version,
            unit_id=unit_id,
            kind=EvidenceKind.DETECTION,
            finding_key=finding_key,
            cwe=cwe.strip().upper(),
            raw_score=raw_score,
            confidence=confidence,
            explanation=explanation,
            artifacts=list(artifacts or []),
        )

    @classmethod
    def silence(
        cls,
        agent_id: str,
        agent_version: str,
        unit_id: str,
        covered_cwes: frozenset[str] | set[str] | list[str],
        explanation: str = "",
    ) -> Evidence:
        """Ran to completion and found nothing, across `covered_cwes`.

        Returning `[]` instead of this is a bug: it is indistinguishable from a
        failure, and it discards the only evidence that can lower a posterior.
        """
        return cls(
            agent_id=agent_id,
            agent_version=agent_version,
            unit_id=unit_id,
            kind=EvidenceKind.SILENCE,
            covered_cwes=frozenset(c.strip().upper() for c in covered_cwes),
            confidence=1.0,
            explanation=explanation or "Analysed the unit and found nothing.",
        )

    @classmethod
    def abstention(
        cls,
        agent_id: str,
        agent_version: str,
        unit_id: str,
        reason: str,
        explanation: str = "",
    ) -> Evidence:
        """Could not run, or could not run soundly. Contributes LR 1.0 — nothing."""
        return cls(
            agent_id=agent_id,
            agent_version=agent_version,
            unit_id=unit_id,
            kind=EvidenceKind.ABSTENTION,
            reason=reason,
            confidence=0.0,
            explanation=explanation or f"Abstained: {reason}",
        )

    # -- convenience --------------------------------------------------------

    @property
    def is_detection(self) -> bool:
        return self.kind is EvidenceKind.DETECTION

    def covers(self, cwe: str) -> bool:
        """Whether this agent's SILENCE is informative about `cwe` (D-006)."""
        return cwe.strip().upper() in self.covered_cwes
