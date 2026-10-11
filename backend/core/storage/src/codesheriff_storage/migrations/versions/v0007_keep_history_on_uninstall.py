"""Uninstalling the App, or deselecting a repository, hides history instead of deleting it.

Revision ID: 0007_keep_history_on_uninstall
Revises: 0006_better_auth
Created: D-102

Until now an `installation` webhook with action `deleted` removed the installation, and the foreign
keys cascaded through repositories, audits, change units, evidence, findings and patch proposals.
An accidental or temporary uninstall therefore erased every result CodeSheriff had recorded for
that account, permanently. Deselecting one repository did the same to that repository.

Two nullable timestamps replace the deletes. A repository with `removed_at` set is invisible to
every dashboard query; an installation with `uninstalled_at` set is not listed as connected. GitHub
keeps repository ids stable, so when a repository is reported again (re-selected, or the App is
installed afresh under a new installation id) its row is un-marked and moved, and its audits are
visible again.

No server default on either column: NULL means "present", which is what every existing row is.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0007_keep_history_on_uninstall"
down_revision: str | None = "0006_better_auth"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "installations", sa.Column("uninstalled_at", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column(
        "repositories", sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("repositories", "removed_at")
    op.drop_column("installations", "uninstalled_at")
