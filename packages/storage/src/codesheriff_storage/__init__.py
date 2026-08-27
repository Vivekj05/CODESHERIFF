"""CodeSheriff persistence.

Imported by `apps/worker` (writes) and `apps/api` (reads). Never by an agent, and never by
`codesheriff_engine` — see D-025 and the `lint-imports` contracts in the root `pyproject.toml`.
"""

from codesheriff_storage.config import DEFAULT_DATABASE_URL, StorageConfig
from codesheriff_storage.identity import (
    create_session,
    hash_session_token,
    list_repositories,
    purge_expired_sessions,
    revoke_session,
    session_for_token,
    set_analysis_enabled,
    touch_session,
    upsert_installation,
    upsert_repository,
    upsert_user,
)
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
    Session,
    User,
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
    "Session",
    "StorageConfig",
    "User",
    "build_chunk",
    "build_engine",
    "build_session_factory",
    "create_session",
    "hash_session_token",
    "is_wellformed_finding_key",
    "list_repositories",
    "persistable_findings",
    "purge_expired_sessions",
    "revoke_session",
    "search_precedents",
    "session_for_token",
    "session_scope",
    "set_analysis_enabled",
    "sha256_text",
    "to_change_unit_row",
    "to_evidence_row",
    "to_finding",
    "touch_session",
    "upsert_installation",
    "upsert_repository",
    "upsert_user",
]
