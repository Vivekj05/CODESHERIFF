"""Webhook delivery idempotency, and `superseded` as a status of its own.

Revision ID: 0003_webhook_deliveries
Revises: 0002_users_and_sessions
Created: Chapter 6

Two changes, both consequences of D-034 meeting a real delivery stream:

- `audits.delivery_id` is unique, so GitHub's at-least-once redelivery of one webhook cannot open a
  second run for work already queued (D-038).
- `audit_status` gains `superseded`. D-034 says an audit for a superseded head is abandoned rather
  than finished; recording that as `failed` would mark the dashboard red for the most ordinary
  thing a developer does, and would make the error rate meaningless (D-039).

Postgres will not let `ALTER TYPE ... ADD VALUE` be used in the same transaction that adds it, and
Alembic runs a migration in one transaction. So the enum is replaced rather than extended: new
type, cast the column across, drop the old, rename. That also gives the downgrade somewhere to put
the rows whose value is about to stop existing.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003_webhook_deliveries"
down_revision: str | None = "0002_users_and_sessions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_VALUES = ("queued", "running", "succeeded", "failed")
_NEW_VALUES = ("queued", "running", "succeeded", "failed", "superseded")


FAILURE_HAS_REASON = "ck_audits_failure_has_reason"
FAILURE_HAS_REASON_SQL = "status <> 'failed' OR error_reason IS NOT NULL"


def _swap_status_enum(values: tuple[str, ...]) -> None:
    """Retype `audits.status` onto a fresh `audit_status` carrying exactly `values`.

    The CHECK constraint from 0001 has to come off first. Postgres stores it with the literal
    already resolved to the *old* enum type, so retyping the column leaves the expression comparing
    `audit_status_new <> audit_status`, and the ALTER fails with "operator does not exist". Dropping
    and recreating it re-resolves the literal against whichever type the column now has.
    """
    rendered = ", ".join(f"'{value}'" for value in values)
    op.drop_constraint(FAILURE_HAS_REASON, "audits", type_="check")
    op.execute(f"CREATE TYPE audit_status_new AS ENUM ({rendered})")
    op.execute(
        "ALTER TABLE audits ALTER COLUMN status TYPE audit_status_new "
        "USING status::text::audit_status_new"
    )
    op.execute("DROP TYPE audit_status")
    op.execute("ALTER TYPE audit_status_new RENAME TO audit_status")
    op.create_check_constraint(FAILURE_HAS_REASON, "audits", FAILURE_HAS_REASON_SQL)


def upgrade() -> None:
    op.add_column("audits", sa.Column("delivery_id", sa.String(length=64), nullable=True))
    # Unique rather than a plain index: the constraint IS the idempotency guarantee. An index would
    # make the duplicate check fast and still let a race insert the second row.
    op.create_unique_constraint("uq_audits_delivery_id", "audits", ["delivery_id"])
    _swap_status_enum(_NEW_VALUES)


def downgrade() -> None:
    # `superseded` is about to stop being expressible. Fold those rows into the nearest surviving
    # state and say why, or the CHECK constraint added in 0001 rejects them.
    op.execute(
        "UPDATE audits SET status = 'failed', "
        "error_reason = COALESCE(error_reason, 'superseded by a later head') "
        "WHERE status = 'superseded'"
    )
    _swap_status_enum(_OLD_VALUES)
    op.drop_constraint("uq_audits_delivery_id", "audits", type_="unique")
    op.drop_column("audits", "delivery_id")
