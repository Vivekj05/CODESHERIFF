"""An audit records the summary comment it posted, word for word.

Revision ID: 0008_audit_comment_body
Revises: 0007_keep_history_on_uninstall
Created: D-103

The dashboard shows what the pull request's author was told. GitHub cannot answer that for an older
audit: there is one summary comment per pull request, edited in place on every push (D-034), so
fetching it returns the latest audit's text under every earlier one. Re-rendering it from the rows
would explain an old audit with today's renderer, the argument D-090 made about the odds product.
The body is therefore written once, by the worker, beside the comment id it belongs to.

It is safe to keep. `comment.py` builds it from closed sets and numbers only: no source, no file
path, no model prose (D-050), so storing it does not breach "persisted records hold findings,
evidence and hashes".

No backfill. NULL means "posted before the body was recorded", and the dashboard says so rather
than reconstructing one.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0008_audit_comment_body"
down_revision: str | None = "0007_keep_history_on_uninstall"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("audits", sa.Column("github_comment_body", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("audits", "github_comment_body")
