"""Every table CodeSheriff has.

The contract's invariants are restated here as CHECK constraints (D-026). That duplication is
deliberate. Every defect in `AUDIT.md` Tier 1 was an invariant enforced in exactly one place and
then bypassed from another: the vendored contract's checksum was rewritten to make its test pass,
and raw string keys such as `abstain:{unit_id}` walked straight past a Pydantic model that only
knew about the fields it declared. A `finding_key` that is not sixteen hex characters is now
rejected by the database, whatever produced it.

Source code is not stored (§6, D-027). `change_units` carries hashes, line numbers and symbol
names. The two places excerpts are permitted — `evidence.artifacts` and `precedent_chunks.content`
— are capped by `redaction.py` on the way in, and the chunk cap is a constraint here as well.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from codesheriff_contracts import IN_SCOPE_CWES
from codesheriff_storage.redaction import MAX_ARTIFACTS_BYTES, MAX_CHUNK_BYTES

EMBEDDING_DIM = 384
"""`BAAI/bge-small-en-v1.5`, per §4. Fixed at the schema level: a different model means a different
column, and a migration is the correct amount of friction for a change that invalidates every
stored vector."""

FINDING_KEY_PATTERN = "^[0-9a-f]{16}$"
"""`finding_key()` returns `sha256(...)[:16]`. Anything else is a hand-rolled key.

This is what stops `fuse_all_evidence`'s synthetic `abstention:all_agents` key from being persisted
as a finding — the same AUDIT.md 1.1 bypass one layer up, in `FusionResult`, where the Evidence
validator cannot see it."""

_CWE_SQL_LIST = ", ".join(f"'{cwe}'" for cwe in sorted(IN_SCOPE_CWES))
"""`IN_SCOPE_CWES` as a SQL literal list, generated from the contract so the two cannot drift.

Widening the set therefore requires a migration. That is intended: the set is closed (§6), and
every fitted number is fitted against it."""


class Base(DeclarativeBase):
    """Declarative base for every CodeSheriff table."""

    type_annotation_map = {  # noqa: RUF012
        datetime: DateTime(timezone=True),
    }


class AuditStatus(StrEnum):
    """Lifecycle of one analysis run. Set by the worker, read by the dashboard.

    `SUPERSEDED` is a terminal state distinct from `FAILED` (D-039). A push to a PR branch abandons
    the run for the previous head — its findings would describe code no longer at the head, and
    D-034 requires it abandoned rather than finished. Recording that as a failure would put a red
    mark on the dashboard for the single most ordinary thing a developer does, and would make the
    error rate unreadable.
    """

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SUPERSEDED = "superseded"


OPEN_AUDIT_STATUSES = (AuditStatus.QUEUED, AuditStatus.RUNNING)
"""The non-terminal states. An audit in one of these can still be superseded."""


class EvidenceKindDB(StrEnum):
    """Mirror of `contracts.EvidenceKind` for the database enum.

    Not the contract enum itself: a Postgres enum type is part of the schema, and binding it
    directly to the contract would let a contract edit silently require a migration nobody wrote.
    `test_models.py` asserts the two sets are identical, so drift fails a test instead.
    """

    DETECTION = "detection"
    SILENCE = "silence"
    ABSTENTION = "abstention"


# Store the lowercase values, not the Python member names — the API and the dashboard serialise the
# same strings the StrEnums do.
_audit_status_enum = Enum(
    AuditStatus,
    name="audit_status",
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
)

_evidence_kind_enum = Enum(
    EvidenceKindDB,
    name="evidence_kind",
    values_callable=lambda enum_cls: [member.value for member in enum_cls],
)


class User(Base):
    """One signed-in GitHub user. Identity only.

    §6 puts multi-tenancy with billing out of scope, and this table is where that would creep in
    first. There are no roles, no teams, no plans and no per-repository grants: what a user may see
    is derived from GitHub at sign-in and held in their session, never stored as an ACL here
    (D-035). A stored ACL is a copy of GitHub's answer that starts going stale immediately.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    """The GitHub user id — stable across renames, which `login` is not."""

    login: Mapped[str] = mapped_column(String(255), nullable=False)
    name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(nullable=True)

    sessions: Mapped[list[Session]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    """One signed-in browser session.

    Two deliberate absences.

    **No GitHub token is stored.** The OAuth access token is used once, at sign-in, to read the
    user's identity and the installations they can see, and is then discarded. Nothing here can be
    replayed against GitHub if this database leaks (D-036).

    **The session token itself is not stored either** — only `token_sha256`. The cookie holds the
    secret; the database holds a hash of it, so a database read does not hand over live sessions.
    """

    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )

    token_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    """SHA-256 of the opaque cookie value. Never the value itself."""

    visible_installation_ids: Mapped[list[int]] = mapped_column(
        ARRAY(BigInteger), nullable=False, default=list
    )
    """Installations this user could see at sign-in, from `GET /user/installations`.

    A snapshot, and knowingly so: access granted or revoked on GitHub is reflected at the user's
    next sign-in rather than immediately (D-035). The alternative — storing a GitHub credential to
    re-ask on every request — trades a bounded staleness window for a permanent secret at rest.
    """

    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(nullable=True)

    user: Mapped[User] = relationship(back_populates="sessions")

    __table_args__ = (
        Index("ix_sessions_expires_at", "expires_at"),
        CheckConstraint("length(token_sha256) = 64", name="ck_sessions_token_hash_length"),
        CheckConstraint("expires_at > created_at", name="ck_sessions_expiry_after_creation"),
    )


class Installation(Base):
    """One GitHub App installation.

    §6 puts multi-tenancy with billing out of scope, so this is GitHub identity and nothing else:
    no roles, no organisations, no plans, no seats.
    """

    __tablename__ = "installations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    """The GitHub installation id. Supplied by GitHub, never generated here."""

    account_login: Mapped[str] = mapped_column(String(255), nullable=False)
    account_type: Mapped[str] = mapped_column(String(32), nullable=False, default="User")
    suspended_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    repositories: Mapped[list[Repository]] = relationship(
        back_populates="installation", cascade="all, delete-orphan"
    )


class Repository(Base):
    """One connected repository."""

    __tablename__ = "repositories"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=False)
    """The GitHub repository id — stable across renames, which `full_name` is not."""

    installation_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("installations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    full_name: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    default_branch: Mapped[str] = mapped_column(String(255), nullable=False, default="main")
    is_private: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    analysis_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        server_default=func.now(), onupdate=func.now(), nullable=False
    )

    installation: Mapped[Installation] = relationship(back_populates="repositories")
    audits: Mapped[list[Audit]] = relationship(
        back_populates="repository", cascade="all, delete-orphan"
    )


class CalibrationRun(Base):
    """One fitted calibration artifact — and the provenance of every posterior fitted with it.

    Chapter 14 writes rows here from the calibration split. It exists now because `audits` and
    `findings` reference it: a stored probability that cannot name the artifact that produced it is
    not a calibrated number, it is a number.

    `is_provisional` is the load-bearing column. Until Chapter 14 runs, fusion uses the hand-set
    ratios in `EngineConfig.likelihood_table`, and D-010 requires that nothing hand-set is ever
    presented as calibrated. Provisional rows are how the dashboard knows to say so.
    """

    __tablename__ = "calibration_runs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    contract_version: Mapped[str] = mapped_column(String(32), nullable=False)
    is_provisional: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    corpus_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    """Hash of the corpus the ratios were fitted on. NULL only while provisional — §6 requires a
    fitted artifact to be reproducible from a recorded corpus."""

    split_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fitted_likelihoods: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    prior_probability: Mapped[float] = mapped_column(Float, nullable=False)
    alert_threshold: Mapped[float] = mapped_column(Float, nullable=False)

    ece: Mapped[float | None] = mapped_column(Float, nullable=True)
    """Expected calibration error on the split named by `split_hash`. A mandatory acceptance
    criterion (§6), so it is a column rather than a line in a notebook."""

    brier: Mapped[float | None] = mapped_column(Float, nullable=True)
    n_cases: Mapped[int | None] = mapped_column(Integer, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    __table_args__ = (
        CheckConstraint(
            "prior_probability > 0.0 AND prior_probability < 1.0",
            name="ck_calibration_prior_range",
        ),
        CheckConstraint(
            "alert_threshold >= 0.0 AND alert_threshold <= 1.0",
            name="ck_calibration_threshold_range",
        ),
        CheckConstraint(
            "is_provisional OR (corpus_hash IS NOT NULL AND split_hash IS NOT NULL)",
            name="ck_calibration_fitted_is_reproducible",
        ),
    )


class Audit(Base):
    """One analysis of one pull request head commit."""

    __tablename__ = "audits"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    repository_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False
    )
    pr_number: Mapped[int] = mapped_column(Integer, nullable=False)
    base_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    head_sha: Mapped[str] = mapped_column(String(40), nullable=False)

    delivery_id: Mapped[str | None] = mapped_column(String(64), nullable=True, unique=True)
    """`X-GitHub-Delivery` of the webhook that created this audit. Unique, so GitHub's at-least-once
    redelivery cannot open a second run for work already queued (D-038). Nullable: an audit created
    by any other route — a replay from the corpus, a manual re-run — has no delivery behind it."""
    status: Mapped[AuditStatus] = mapped_column(
        _audit_status_enum, nullable=False, default=AuditStatus.QUEUED
    )
    contract_version: Mapped[str] = mapped_column(String(32), nullable=False)

    calibration_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("calibration_runs.id", ondelete="RESTRICT"), nullable=True
    )
    """Which fitted artifact this run's posteriors came from. RESTRICT, not CASCADE: deleting a
    calibration artifact must not silently delete the findings that cite it."""

    prior_probability: Mapped[float] = mapped_column(Float, nullable=False)
    alert_threshold: Mapped[float] = mapped_column(Float, nullable=False)

    started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    error_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    github_comment_id: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    repository: Mapped[Repository] = relationship(back_populates="audits")
    calibration_run: Mapped[CalibrationRun | None] = relationship()
    change_units: Mapped[list[ChangeUnitRow]] = relationship(
        back_populates="audit", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="audit", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Deliberately not unique on (repository_id, head_sha): re-analysing the same commit under
        # a new calibration artifact is exactly how a recalibration gets evaluated.
        Index("ix_audits_repo_pr", "repository_id", "pr_number"),
        Index("ix_audits_head_sha", "head_sha"),
        CheckConstraint(
            "status <> 'failed' OR error_reason IS NOT NULL",
            name="ck_audits_failure_has_reason",
        ),
    )


class ChangeUnitRow(Base):
    """One analysed function. Metadata and hashes only — never `pre_src` or `post_src` (§6).

    Named `ChangeUnitRow` rather than `ChangeUnit` on purpose. The contract's `ChangeUnit` carries
    the source; this row deliberately cannot. Giving them one name is how someone eventually writes
    `ChangeUnit(**row.__dict__)` and persists a function body.
    """

    __tablename__ = "change_units"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    audit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False
    )
    unit_id: Mapped[str] = mapped_column(String(255), nullable=False)
    file: Mapped[str] = mapped_column(String(1024), nullable=False)

    qualified_symbol: Mapped[str] = mapped_column(String(512), nullable=False)
    """`ChangeUnit.qualified_symbol`, stored as the unit reported it. Never reassembled from
    `symbol` and `enclosing_class` at read time — that is the D-004 divergence by another route."""

    symbol: Mapped[str | None] = mapped_column(String(255), nullable=True)
    enclosing_class: Mapped[str | None] = mapped_column(String(255), nullable=True)
    language: Mapped[str] = mapped_column(String(32), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    changed_lines: Mapped[list[int]] = mapped_column(ARRAY(Integer), nullable=False, default=list)

    decorators: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    """Decorator names only, no bodies. Their removal is the whole signal for CWE-862 and CWE-639
    (D-013), so a findings page that cannot show which decorator vanished cannot explain those."""

    is_test_file: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    post_src_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    """Hash, not source. Lets a re-run recognise an unchanged unit and reuse its evidence, which is
    part of how the semantic agent stays inside its per-unit cost ceiling."""

    pre_src_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    post_src_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    post_src_lines: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    audit: Mapped[Audit] = relationship(back_populates="change_units")
    evidence: Mapped[list[EvidenceRow]] = relationship(
        back_populates="change_unit", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("audit_id", "unit_id", name="uq_change_units_audit_unit"),
        CheckConstraint("length(post_src_sha256) = 64", name="ck_change_units_post_sha_length"),
    )


class EvidenceRow(Base):
    """One agent's statement about one change unit.

    The three-kind invariants from `contracts.Evidence._check_kind_invariants` are repeated here as
    constraints. An `INSERT` that bypasses the Pydantic model — a raw SQL fixture, a dashboard
    write, a future backfill script — meets the same rules (D-026).
    """

    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    change_unit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("change_units.id", ondelete="CASCADE"), nullable=False
    )
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_version: Mapped[str] = mapped_column(String(32), nullable=False)
    kind: Mapped[EvidenceKindDB] = mapped_column(_evidence_kind_enum, nullable=False)

    finding_key: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(16), nullable=True)
    covered_cwes: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, default=list)
    reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    raw_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    explanation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    artifacts: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    change_unit: Mapped[ChangeUnitRow] = relationship(back_populates="evidence")

    __table_args__ = (
        Index("ix_evidence_change_unit", "change_unit_id"),
        Index("ix_evidence_finding_key", "finding_key"),
        Index("ix_evidence_agent", "agent_id"),
        CheckConstraint(
            "kind <> 'detection' OR (finding_key IS NOT NULL AND cwe IS NOT NULL "
            "AND cardinality(covered_cwes) = 0 AND reason IS NULL)",
            name="ck_evidence_detection_shape",
        ),
        CheckConstraint(
            "kind = 'detection' OR (finding_key IS NULL AND cwe IS NULL)",
            name="ck_evidence_non_detection_has_no_key",
        ),
        CheckConstraint(
            "kind <> 'silence' OR cardinality(covered_cwes) > 0",
            name="ck_evidence_silence_has_covered_cwes",
        ),
        CheckConstraint(
            "kind <> 'abstention' OR reason IS NOT NULL",
            name="ck_evidence_abstention_has_reason",
        ),
        CheckConstraint(
            "kind = 'abstention' OR reason IS NULL",
            name="ck_evidence_reason_is_abstention_only",
        ),
        CheckConstraint(
            f"finding_key IS NULL OR finding_key ~ '{FINDING_KEY_PATTERN}'",
            name="ck_evidence_finding_key_format",
        ),
        CheckConstraint(
            f"cwe IS NULL OR cwe IN ({_CWE_SQL_LIST})",
            name="ck_evidence_cwe_in_scope",
        ),
        CheckConstraint(
            f"covered_cwes <@ ARRAY[{_CWE_SQL_LIST}]::text[]",
            name="ck_evidence_covered_cwes_in_scope",
        ),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_evidence_confidence"),
        CheckConstraint(
            f"octet_length(artifacts::text) <= {MAX_ARTIFACTS_BYTES}",
            name="ck_evidence_artifacts_budget",
        ),
    )


class Finding(Base):
    """One fused posterior for one `finding_key` within one audit."""

    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    audit_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False
    )
    finding_key: Mapped[str] = mapped_column(String(16), nullable=False)
    cwe: Mapped[str] = mapped_column(String(16), nullable=False)
    posterior_probability: Mapped[float] = mapped_column(Float, nullable=False)
    is_alert_worthy: Mapped[bool] = mapped_column(Boolean, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")

    prior_probability: Mapped[float] = mapped_column(Float, nullable=False)
    alert_threshold: Mapped[float] = mapped_column(Float, nullable=False)
    """The threshold *at the time of the run*. Selecting a new threshold later must not
    retroactively rewrite which past findings were alerts — that would make the evaluation
    unfalsifiable."""

    calibration_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("calibration_runs.id", ondelete="RESTRICT"), nullable=True
    )
    file: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    qualified_symbol: Mapped[str | None] = mapped_column(String(512), nullable=True)
    line_numbers: Mapped[list[int]] = mapped_column(ARRAY(Integer), nullable=False, default=list)
    title: Mapped[str] = mapped_column(Text, nullable=False, default="")
    consensus_rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    audit: Mapped[Audit] = relationship(back_populates="findings")
    calibration_run: Mapped[CalibrationRun | None] = relationship()

    __table_args__ = (
        UniqueConstraint("audit_id", "finding_key", name="uq_findings_audit_key"),
        CheckConstraint(
            f"finding_key ~ '{FINDING_KEY_PATTERN}'", name="ck_findings_finding_key_format"
        ),
        CheckConstraint(f"cwe IN ({_CWE_SQL_LIST})", name="ck_findings_cwe_in_scope"),
        CheckConstraint(
            "posterior_probability >= 0.0 AND posterior_probability <= 1.0",
            name="ck_findings_posterior_range",
        ),
        CheckConstraint(
            "is_alert_worthy = (posterior_probability >= alert_threshold)",
            name="ck_findings_alert_matches_threshold",
        ),
    )


class PRPrecedent(Base):
    """One merged pull request, as precedent for the context agent.

    This is the repository's own history — `context.rag` decides on precedent, and its documented
    failure mode is a repository that has none. Rows here are that memory.
    """

    __tablename__ = "pr_precedents"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    repository_id: Mapped[int] = mapped_column(
        BigInteger, ForeignKey("repositories.id", ondelete="CASCADE"), nullable=False
    )
    pr_number: Mapped[int] = mapped_column(Integer, nullable=False)
    head_sha: Mapped[str] = mapped_column(String(40), nullable=False)
    merged_at: Mapped[datetime | None] = mapped_column(nullable=True)
    files_changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    ingested_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    chunks: Mapped[list[PrecedentChunk]] = relationship(
        back_populates="precedent", cascade="all, delete-orphan"
    )

    __table_args__ = (
        UniqueConstraint("repository_id", "pr_number", name="uq_pr_precedents_repo_pr"),
    )


class PrecedentChunk(Base):
    """One embedded excerpt of merged code, and its vector.

    The 384-dim column is why Postgres carries pgvector rather than the project carrying ChromaDB
    (D-016): similarity search and metadata filtering resolve in one query, and the store survives
    a restart.

    `content` holds a bounded excerpt, capped by `redaction.redact_chunk` and by the constraint
    below (D-027). Embeddings alone would be unusable — retrieval could neither be shown as
    evidence in a comment nor re-embedded when the model changes.
    """

    __tablename__ = "precedent_chunks"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    precedent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("pr_precedents.id", ondelete="CASCADE"), nullable=False
    )
    file: Mapped[str] = mapped_column(String(1024), nullable=False)
    qualified_symbol: Mapped[str | None] = mapped_column(String(512), nullable=True)
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    embedding: Mapped[list[float]] = mapped_column(Vector(EMBEDDING_DIM), nullable=False)
    embedding_model: Mapped[str] = mapped_column(
        String(128), nullable=False, default="BAAI/bge-small-en-v1.5"
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(), nullable=False)

    precedent: Mapped[PRPrecedent] = relationship(back_populates="chunks")

    __table_args__ = (
        UniqueConstraint(
            "precedent_id", "file", "chunk_index", name="uq_precedent_chunks_position"
        ),
        CheckConstraint(
            f"octet_length(content) <= {MAX_CHUNK_BYTES}",
            name="ck_precedent_chunks_excerpt_budget",
        ),
        # HNSW rather than IVFFlat: IVFFlat needs representative data present before its lists can
        # be trained, and this index is created on an empty table. Declared here as well as in the
        # migration because Alembic compares the database against this metadata — an index created
        # only by raw SQL reads as "drift, remove it" on the next autogenerate.
        Index(
            "ix_precedent_chunks_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )
