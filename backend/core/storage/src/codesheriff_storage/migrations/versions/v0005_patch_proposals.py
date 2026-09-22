"""What the patcher did about each alert-worthy finding — including when it did nothing.

Revision ID: 0005_patch_proposals
Revises: 0004_finding_contributions
Created: Chapter 17

One row per alert-worthy finding, whether or not a suggestion was posted. A table holding only the
published patches would report "the model was never asked, the function was over the size budget"
and "three repairs were drafted and every one failed a check" as the same silence, and only the
second of those is a defect report waiting to be written.

**The patch itself is deliberately absent** (D-097). `patch_sha256` is the whole of it. §6 keeps
source out of the database, and a repaired function is somebody else's source with our edit in it;
if it was published it already lives in the pull request, under the control of the person who owns
it. The digest answers the only question a row needs to — whether two audits proposed the same
repair — and answers it without a second uncontrolled copy.

`checks` is stored rather than recomputed, for the reason `findings.contributions` is (D-090): a
rung's outcome is a property of the run, and re-deriving it later would judge an old proposal by
today's witnesses. It carries the same three-state discipline as the column above it — NULL means
no draft ever reached verification, and the CHECK keeps an empty array and the JSON scalar `null`
out.

`published` is a fact about GitHub rather than about the patch. A verified, anchorable repair the
API refused is `verified` and unpublished, which is this system failing rather than the repair.

Only `created_at` carries a server default, matching every other table here: the Python-side
defaults on the model fill the rest, and a server default the model does not declare shows up as
permanent drift in `test_no_pending_schema_changes` — which is exactly how this was found.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005_patch_proposals"
down_revision: str | None = "0004_finding_contributions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PATCH_OUTCOMES = (
    "verified",
    "not_anchorable",
    "unverified",
    "no_repair_offered",
    "patcher_unavailable",
    "unit_too_large",
    "unparseable_unit",
    "disabled",
    "not_alert_worthy",
)


def upgrade() -> None:
    outcome = postgresql.ENUM(*PATCH_OUTCOMES, name="patch_outcome", create_type=False)
    outcome.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "patch_proposals",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "finding_id",
            sa.Uuid(),
            sa.ForeignKey("findings.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("outcome", outcome, nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("drafts_requested", sa.Integer(), nullable=False),
        sa.Column(
            "checks",
            postgresql.JSONB(astext_type=sa.Text(), none_as_null=True),
            nullable=True,
        ),
        sa.Column("patch_sha256", sa.String(length=64), nullable=True),
        sa.Column("published", sa.Boolean(), nullable=False),
        sa.Column("github_comment_id", sa.BigInteger(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.UniqueConstraint("finding_id", name="uq_patch_proposals_finding"),
        sa.CheckConstraint("drafts_requested >= 0", name="ck_patch_proposals_drafts_non_negative"),
        sa.CheckConstraint(
            "checks IS NULL OR (jsonb_typeof(checks) = 'array' AND jsonb_array_length(checks) > 0)",
            name="ck_patch_proposals_checks_shape",
        ),
        sa.CheckConstraint(
            "patch_sha256 IS NULL OR patch_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_patch_proposals_sha_format",
        ),
        sa.CheckConstraint(
            "published = false OR (patch_sha256 IS NOT NULL AND outcome = 'verified')",
            name="ck_patch_proposals_published_has_a_patch",
        ),
        sa.CheckConstraint(
            "github_comment_id IS NULL OR published = true",
            name="ck_patch_proposals_comment_implies_published",
        ),
    )


def downgrade() -> None:
    op.drop_table("patch_proposals")
    postgresql.ENUM(name="patch_outcome").drop(op.get_bind(), checkfirst=True)
