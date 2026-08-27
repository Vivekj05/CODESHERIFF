"""The single shared CodeSheriff contract.

Imported by every agent, the engine, and the apps. It is the ONLY thing an agent is
permitted to import (enforced by import-linter; see the root pyproject.toml).

Do not vendor this package. Four byte-identical copies previously existed, kept in
sync by a SHA-256 test whose expected hash was rewritten to make it pass. See
DECISIONS.md D-002 and AUDIT.md 4.8.
"""

from codesheriff_contracts.contracts import (
    CONTRACT_VERSION,
    IN_SCOPE_CWES,
    Artifact,
    ChangeUnit,
    Evidence,
    EvidenceKind,
    PRContext,
    finding_key,
)

__all__ = [
    "CONTRACT_VERSION",
    "IN_SCOPE_CWES",
    "Artifact",
    "ChangeUnit",
    "Evidence",
    "EvidenceKind",
    "PRContext",
    "finding_key",
]
