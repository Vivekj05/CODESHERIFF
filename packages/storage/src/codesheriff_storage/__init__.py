"""CodeSheriff persistence.

Imported by `apps/worker` (writes) and `apps/api` (reads). Never by an agent, and never by
`codesheriff_engine` — see D-025 and the `lint-imports` contracts in the root `pyproject.toml`.
"""

from codesheriff_storage.config import DEFAULT_DATABASE_URL, StorageConfig
from codesheriff_storage.mapping import (
    is_wellformed_finding_key,
    persistable_findings,
    sha256_text,
    to_change_unit_row,
    to_evidence_row,
    to_finding,
)
from codesheriff_storage.models import (
    EMBEDDING_DIM,
    FINDING_KEY_PATTERN,
    Audit,
    AuditStatus,
    Base,
    CalibrationRun,
    ChangeUnitRow,
    EvidenceKindDB,
    EvidenceRow,
    Finding,
    Installation,
    PrecedentChunk,
    PRPrecedent,
    Repository,
)
from codesheriff_storage.precedents import PrecedentMatch, build_chunk, search_precedents
from codesheriff_storage.session import build_engine, build_session_factory, session_scope

__all__ = [
    "DEFAULT_DATABASE_URL",
    "EMBEDDING_DIM",
    "FINDING_KEY_PATTERN",
    "Audit",
    "AuditStatus",
    "Base",
    "CalibrationRun",
    "ChangeUnitRow",
    "EvidenceKindDB",
    "EvidenceRow",
    "Finding",
    "Installation",
    "PRPrecedent",
    "PrecedentChunk",
    "PrecedentMatch",
    "Repository",
    "StorageConfig",
    "build_chunk",
    "build_engine",
    "build_session_factory",
    "is_wellformed_finding_key",
    "persistable_findings",
    "search_precedents",
    "session_scope",
    "sha256_text",
    "to_change_unit_row",
    "to_evidence_row",
    "to_finding",
]
