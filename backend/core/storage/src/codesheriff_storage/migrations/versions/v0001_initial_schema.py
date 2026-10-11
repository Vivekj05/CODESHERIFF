"""Initial schema: installations through precedent_chunks, with pgvector enabled.

Revision ID: 0001_initial_schema
Revises:
Created: Chapter 3

The CWE list and the `finding_key` pattern are written out literally here rather than imported
from `codesheriff_contracts`. A migration is a historical record: it must produce the same schema
in five years' time, when the contract may have moved on. `test_migrations.py` compares the
migrated database against the live metadata, so drift between the two fails a test rather than
silently applying.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from pgvector.sqlalchemy import Vector
from sqlalchemy.dialects import postgresql

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen copy of IN_SCOPE_CWES at contract v2.0.0, in `sorted()` order. Widening the closed set
# means a new migration — which is the intended amount of friction for a change that invalidates
# every number fitted against it (§6).
_CWES = (
    "'CWE-22', 'CWE-502', 'CWE-639', 'CWE-78', 'CWE-79', "
    "'CWE-798', 'CWE-862', 'CWE-89', 'CWE-918', 'CWE-94'"
)
_FINDING_KEY_PATTERN = "^[0-9a-f]{16}$"
_EMBEDDING_DIM = 384
_MAX_ARTIFACTS_BYTES = 8192
_MAX_CHUNK_BYTES = 4096

audit_status = postgresql.ENUM(
    "queued", "running", "succeeded", "failed", name="audit_status", create_type=False
)
evidence_kind = postgresql.ENUM(
    "detection", "silence", "abstention", name="evidence_kind", create_type=False
)


def upgrade() -> None:
    bind = op.get_bind()

    # docker-compose runs scripts/init-pgvector.sql on first boot of an empty volume only. A CI
    # service container or a hand-created database never sees it, so the extension is declared
    # here too — idempotently.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    audit_status.create(bind, checkfirst=True)
    evidence_kind.create(bind, checkfirst=True)

    op.create_table(
        "installations",
        sa.Column("id", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("account_login", sa.String(length=255), nullable=False),
        sa.Column("account_type", sa.String(length=32), nullable=False),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "repositories",
        sa.Column("id", sa.BigInteger(), autoincrement=False, nullable=False),
        sa.Column("installation_id", sa.BigInteger(), nullable=False),
        sa.Column("full_name", sa.String(length=512), nullable=False),
        sa.Column("default_branch", sa.String(length=255), nullable=False),
        sa.Column("is_private", sa.Boolean(), nullable=False),
        sa.Column("analysis_enabled", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["installation_id"], ["installations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("full_name"),
    )
    op.create_index("ix_repositories_installation_id", "repositories", ["installation_id"])

    op.create_table(
        "calibration_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("contract_version", sa.String(length=32), nullable=False),
        sa.Column("is_provisional", sa.Boolean(), nullable=False),
        sa.Column("corpus_hash", sa.String(length=64), nullable=True),
        sa.Column("split_hash", sa.String(length=64), nullable=True),
        sa.Column("fitted_likelihoods", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("prior_probability", sa.Float(), nullable=False),
        sa.Column("alert_threshold", sa.Float(), nullable=False),
        sa.Column("ece", sa.Float(), nullable=True),
        sa.Column("brier", sa.Float(), nullable=True),
        sa.Column("n_cases", sa.Integer(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "prior_probability > 0.0 AND prior_probability < 1.0",
            name="ck_calibration_prior_range",
        ),
        sa.CheckConstraint(
            "alert_threshold >= 0.0 AND alert_threshold <= 1.0",
            name="ck_calibration_threshold_range",
        ),
        sa.CheckConstraint(
            "is_provisional OR (corpus_hash IS NOT NULL AND split_hash IS NOT NULL)",
            name="ck_calibration_fitted_is_reproducible",
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "audits",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("repository_id", sa.BigInteger(), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("base_sha", sa.String(length=40), nullable=False),
        sa.Column("head_sha", sa.String(length=40), nullable=False),
        sa.Column("status", audit_status, nullable=False),
        sa.Column("contract_version", sa.String(length=32), nullable=False),
        sa.Column("calibration_run_id", sa.Uuid(), nullable=True),
        sa.Column("prior_probability", sa.Float(), nullable=False),
        sa.Column("alert_threshold", sa.Float(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_reason", sa.Text(), nullable=True),
        sa.Column("github_comment_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status <> 'failed' OR error_reason IS NOT NULL",
            name="ck_audits_failure_has_reason",
        ),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["calibration_run_id"], ["calibration_runs.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audits_repo_pr", "audits", ["repository_id", "pr_number"])
    op.create_index("ix_audits_head_sha", "audits", ["head_sha"])

    op.create_table(
        "change_units",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("unit_id", sa.String(length=255), nullable=False),
        sa.Column("file", sa.String(length=1024), nullable=False),
        sa.Column("qualified_symbol", sa.String(length=512), nullable=False),
        sa.Column("symbol", sa.String(length=255), nullable=True),
        sa.Column("enclosing_class", sa.String(length=255), nullable=True),
        sa.Column("language", sa.String(length=32), nullable=False),
        sa.Column("start_line", sa.Integer(), nullable=False),
        sa.Column("changed_lines", sa.ARRAY(sa.Integer()), nullable=False),
        sa.Column("decorators", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column("is_test_file", sa.Boolean(), nullable=False),
        # Hashes and metadata only. There is deliberately no post_src column (§6, D-027).
        sa.Column("post_src_sha256", sa.String(length=64), nullable=False),
        sa.Column("pre_src_sha256", sa.String(length=64), nullable=True),
        sa.Column("post_src_bytes", sa.Integer(), nullable=False),
        sa.Column("post_src_lines", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("length(post_src_sha256) = 64", name="ck_change_units_post_sha_length"),
        sa.ForeignKeyConstraint(["audit_id"], ["audits.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("audit_id", "unit_id", name="uq_change_units_audit_unit"),
    )

    op.create_table(
        "evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("change_unit_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.String(length=64), nullable=False),
        sa.Column("agent_version", sa.String(length=32), nullable=False),
        sa.Column("kind", evidence_kind, nullable=False),
        sa.Column("finding_key", sa.String(length=16), nullable=True),
        sa.Column("cwe", sa.String(length=16), nullable=True),
        sa.Column("covered_cwes", sa.ARRAY(sa.Text()), nullable=False),
        sa.Column("reason", sa.String(length=64), nullable=True),
        sa.Column("raw_score", sa.Float(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("artifacts", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # The contract's three-kind invariants, restated so an INSERT that never touched the
        # Pydantic model meets the same rules (D-026).
        sa.CheckConstraint(
            "kind <> 'detection' OR (finding_key IS NOT NULL AND cwe IS NOT NULL "
            "AND cardinality(covered_cwes) = 0 AND reason IS NULL)",
            name="ck_evidence_detection_shape",
        ),
        sa.CheckConstraint(
            "kind = 'detection' OR (finding_key IS NULL AND cwe IS NULL)",
            name="ck_evidence_non_detection_has_no_key",
        ),
        sa.CheckConstraint(
            "kind <> 'silence' OR cardinality(covered_cwes) > 0",
            name="ck_evidence_silence_has_covered_cwes",
        ),
        sa.CheckConstraint(
            "kind <> 'abstention' OR reason IS NOT NULL",
            name="ck_evidence_abstention_has_reason",
        ),
        sa.CheckConstraint(
            "kind = 'abstention' OR reason IS NULL",
            name="ck_evidence_reason_is_abstention_only",
        ),
        sa.CheckConstraint(
            f"finding_key IS NULL OR finding_key ~ '{_FINDING_KEY_PATTERN}'",
            name="ck_evidence_finding_key_format",
        ),
        sa.CheckConstraint(f"cwe IS NULL OR cwe IN ({_CWES})", name="ck_evidence_cwe_in_scope"),
        sa.CheckConstraint(
            f"covered_cwes <@ ARRAY[{_CWES}]::text[]",
            name="ck_evidence_covered_cwes_in_scope",
        ),
        sa.CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0", name="ck_evidence_confidence"
        ),
        sa.CheckConstraint(
            f"octet_length(artifacts::text) <= {_MAX_ARTIFACTS_BYTES}",
            name="ck_evidence_artifacts_budget",
        ),
        sa.ForeignKeyConstraint(["change_unit_id"], ["change_units.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_evidence_change_unit", "evidence", ["change_unit_id"])
    op.create_index("ix_evidence_finding_key", "evidence", ["finding_key"])
    op.create_index("ix_evidence_agent", "evidence", ["agent_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("audit_id", sa.Uuid(), nullable=False),
        sa.Column("finding_key", sa.String(length=16), nullable=False),
        sa.Column("cwe", sa.String(length=16), nullable=False),
        sa.Column("posterior_probability", sa.Float(), nullable=False),
        sa.Column("is_alert_worthy", sa.Boolean(), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("prior_probability", sa.Float(), nullable=False),
        sa.Column("alert_threshold", sa.Float(), nullable=False),
        sa.Column("calibration_run_id", sa.Uuid(), nullable=True),
        sa.Column("file", sa.String(length=1024), nullable=True),
        sa.Column("qualified_symbol", sa.String(length=512), nullable=True),
        sa.Column("line_numbers", sa.ARRAY(sa.Integer()), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("consensus_rationale", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        # Sixteen hex characters or nothing. This is what stops a hand-rolled key such as
        # `abstention:all_agents` from being stored as if an agent had produced it.
        sa.CheckConstraint(
            f"finding_key ~ '{_FINDING_KEY_PATTERN}'", name="ck_findings_finding_key_format"
        ),
        sa.CheckConstraint(f"cwe IN ({_CWES})", name="ck_findings_cwe_in_scope"),
        sa.CheckConstraint(
            "posterior_probability >= 0.0 AND posterior_probability <= 1.0",
            name="ck_findings_posterior_range",
        ),
        sa.CheckConstraint(
            "is_alert_worthy = (posterior_probability >= alert_threshold)",
            name="ck_findings_alert_matches_threshold",
        ),
        sa.ForeignKeyConstraint(["audit_id"], ["audits.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["calibration_run_id"], ["calibration_runs.id"], ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("audit_id", "finding_key", name="uq_findings_audit_key"),
    )

    op.create_table(
        "pr_precedents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("repository_id", sa.BigInteger(), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=False),
        sa.Column("head_sha", sa.String(length=40), nullable=False),
        sa.Column("merged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("files_changed", sa.Integer(), nullable=False),
        sa.Column(
            "ingested_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("repository_id", "pr_number", name="uq_pr_precedents_repo_pr"),
    )

    op.create_table(
        "precedent_chunks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("precedent_id", sa.Uuid(), nullable=False),
        sa.Column("file", sa.String(length=1024), nullable=False),
        sa.Column("qualified_symbol", sa.String(length=512), nullable=True),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("embedding", Vector(_EMBEDDING_DIM), nullable=False),
        sa.Column("embedding_model", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"octet_length(content) <= {_MAX_CHUNK_BYTES}",
            name="ck_precedent_chunks_excerpt_budget",
        ),
        sa.ForeignKeyConstraint(["precedent_id"], ["pr_precedents.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "precedent_id", "file", "chunk_index", name="uq_precedent_chunks_position"
        ),
    )

    # HNSW rather than IVFFlat: IVFFlat needs representative data present before its lists can be
    # trained, and this index is created on an empty table. Cosine, matching the normalised vectors
    # BAAI/bge-small-en-v1.5 produces. Declared through create_index rather than raw SQL so it is
    # visible to Alembic's comparison against the models.
    op.create_index(
        "ix_precedent_chunks_embedding_hnsw",
        "precedent_chunks",
        ["embedding"],
        postgresql_using="hnsw",
        postgresql_ops={"embedding": "vector_cosine_ops"},
    )


def downgrade() -> None:
    bind = op.get_bind()

    op.drop_index("ix_precedent_chunks_embedding_hnsw", table_name="precedent_chunks")
    op.drop_table("precedent_chunks")
    op.drop_table("pr_precedents")
    op.drop_table("findings")
    op.drop_index("ix_evidence_agent", table_name="evidence")
    op.drop_index("ix_evidence_finding_key", table_name="evidence")
    op.drop_index("ix_evidence_change_unit", table_name="evidence")
    op.drop_table("evidence")
    op.drop_table("change_units")
    op.drop_index("ix_audits_head_sha", table_name="audits")
    op.drop_index("ix_audits_repo_pr", table_name="audits")
    op.drop_table("audits")
    op.drop_table("calibration_runs")
    op.drop_index("ix_repositories_installation_id", table_name="repositories")
    op.drop_table("repositories")
    op.drop_table("installations")

    evidence_kind.drop(bind, checkfirst=True)
    audit_status.drop(bind, checkfirst=True)

    # The extension is left in place. Other schemas in the same database may be using it, and
    # dropping it would take their vector columns with it.
