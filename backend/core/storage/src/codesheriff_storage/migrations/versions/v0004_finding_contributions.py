"""The odds product, factor by factor, stored beside the posterior it produced.

Revision ID: 0004_finding_contributions
Revises: 0003_webhook_deliveries
Created: Chapter 16

`fusion.bayes` has always produced a `WitnessContribution` per witness — the stance, the
ratio-table cell it selected, the likelihood ratio read from that cell, and the backends that
spoke for it. Until now that breakdown reached the CLI and the pull request comment and was then
discarded, so a stored finding carried a posterior nobody could take apart.

It is **stored** rather than recomputed at read time, for the reason `alert_threshold` is stored
(§6). Re-deriving the factors from today's artifact would explain a finding with ratios it never
used, and the breakdown would contradict the posterior sitting next to it. It would also put a
probability computation behind a read route, which no route in this API performs.

The column is nullable and the CHECK forbids both an empty array and the JSON scalar `null`, so
there are exactly two states a reader has to handle: a recorded breakdown, or none. Rows written
before this migration are the second, and the dashboard says so rather than rendering four absent
witnesses as four neutral ones — a fabricated explanation of a real number is worse than an
admitted gap.

The JSON `null` half of that CHECK is not hypothetical. SQLAlchemy persists Python `None` into a
JSONB column as the JSON scalar `null` unless the type is declared `none_as_null=True`, and a
column holding `'null'::jsonb` reads back as `None` in Python while being NOT NULL in SQL — a
third state wearing the second one's clothes. The model declares the flag; this constraint is
what makes a future writer that forgets it fail loudly instead of quietly.

There is deliberately **no backfill**. The factors are a property of the run, and the evidence
rows that would have to be re-fused are the run's inputs, not its outputs; recomputing them now
would date every historical finding to today's calibration artifact.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0004_finding_contributions"
down_revision: str | None = "0003_webhook_deliveries"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

CONTRIBUTIONS_SHAPE = "ck_findings_contributions_shape"
CONTRIBUTIONS_SHAPE_SQL = (
    "contributions IS NULL OR (jsonb_typeof(contributions) = 'array' "
    "AND jsonb_array_length(contributions) > 0)"
)


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "contributions",
            postgresql.JSONB(astext_type=sa.Text(), none_as_null=True),
            nullable=True,
        ),
    )
    op.create_check_constraint(CONTRIBUTIONS_SHAPE, "findings", CONTRIBUTIONS_SHAPE_SQL)


def downgrade() -> None:
    op.drop_constraint(CONTRIBUTIONS_SHAPE, "findings", type_="check")
    op.drop_column("findings", "contributions")
