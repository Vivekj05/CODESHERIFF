"""Installation and repository rows: what a signed-in user's installations make visible.

Queries live here rather than in `backend/api` so the app layer holds routes and GitHub calls, and
this package holds SQL. Users and sessions are no longer written from Python at all: Better Auth
owns them in the dashboard (D-101), and the API learns who is calling from a verified JWT.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session as DbSession

from codesheriff_storage.models import Installation, Repository


def upsert_installation(
    db: DbSession,
    installation_id: int,
    account_login: str,
    account_type: str,
    suspended_at: datetime | None = None,
) -> Installation:
    """Insert or refresh an installation."""
    stmt = (
        pg_insert(Installation)
        .values(
            id=installation_id,
            account_login=account_login,
            account_type=account_type,
            suspended_at=suspended_at,
        )
        .on_conflict_do_update(
            index_elements=[Installation.id],
            set_={
                "account_login": account_login,
                "account_type": account_type,
                "suspended_at": suspended_at,
                "updated_at": datetime.now(UTC),
            },
        )
        .returning(Installation)
    )
    return db.execute(stmt, execution_options={"populate_existing": True}).scalar_one()


def upsert_repository(
    db: DbSession,
    repo_id: int,
    installation_id: int,
    full_name: str,
    default_branch: str,
    is_private: bool,
) -> Repository:
    """Insert or refresh a repository.

    `analysis_enabled` is deliberately absent from the update set. It is the user's choice, and a
    routine resync from GitHub must not silently re-enable analysis on a repository somebody turned
    off.
    """
    stmt = (
        pg_insert(Repository)
        .values(
            id=repo_id,
            installation_id=installation_id,
            full_name=full_name,
            default_branch=default_branch,
            is_private=is_private,
        )
        .on_conflict_do_update(
            index_elements=[Repository.id],
            set_={
                "installation_id": installation_id,
                "full_name": full_name,
                "default_branch": default_branch,
                "is_private": is_private,
                "updated_at": datetime.now(UTC),
            },
        )
        .returning(Repository)
    )
    return db.execute(stmt, execution_options={"populate_existing": True}).scalar_one()


def list_repositories(
    db: DbSession,
    installation_ids: list[int],
    limit: int = 30,
    after_full_name: str | None = None,
) -> list[Repository]:
    """Repositories visible to a session, keyset-paginated by `full_name`.

    Keyset rather than OFFSET: the dashboard scrolls this list, and an OFFSET page can skip or
    repeat rows when a concurrent installation event inserts a repository above the cursor.

    An empty `installation_ids` returns nothing rather than everything. That asymmetry is the whole
    access check — a session that can see no installations must not fall through to a bare `SELECT
    *` (D-035).
    """
    if not installation_ids:
        return []
    stmt = (
        select(Repository)
        .where(Repository.installation_id.in_(installation_ids))
        .order_by(Repository.full_name)
        .limit(limit)
    )
    if after_full_name:
        stmt = stmt.where(Repository.full_name > after_full_name)
    return list(db.execute(stmt).scalars().all())


def set_analysis_enabled(
    db: DbSession,
    repo_id: int,
    installation_ids: list[int],
    enabled: bool,
) -> Repository | None:
    """Toggle analysis for one repository, scoped to what the session may see.

    Returns None when the repository does not exist *or* is outside the session's installations —
    the caller answers 404 either way rather than distinguishing them, which would confirm the
    existence of a repository the user cannot see.
    """
    if not installation_ids:
        return None
    stmt = select(Repository).where(
        Repository.id == repo_id,
        Repository.installation_id.in_(installation_ids),
    )
    repo = db.execute(stmt).scalar_one_or_none()
    if repo is None:
        return None
    repo.analysis_enabled = enabled
    db.flush()
    return repo


def delete_installation(db: DbSession, installation_id: int) -> bool:
    """Remove an installation and, by cascade, its repositories. Returns whether one existed.

    The App was uninstalled. Keeping the rows would mean the dashboard lists repositories the App
    can no longer read and a webhook for which no token can be minted — and D-035 makes GitHub the
    authority on access, so a stale local copy of a revoked grant is exactly the thing that
    decision exists to prevent.

    Audits cascade with the repository. That is deliberate: an audit records findings about a
    repository this installation no longer grants any access to, and §6 keeps no data whose owner
    has withdrawn the grant.
    """
    result = db.execute(
        delete(Installation).where(Installation.id == installation_id),
        execution_options={"synchronize_session": "fetch"},
    )
    return bool(getattr(result, "rowcount", 0) or 0)


def delete_repositories(db: DbSession, installation_id: int, repo_ids: list[int]) -> int:
    """Remove repositories dropped from an installation. Returns how many went.

    Scoped by `installation_id` as well as by id. The caller is a webhook handler acting on a
    payload, and a delete that trusted only the ids in that payload would be one verification bug
    away from removing another installation's rows.
    """
    if not repo_ids:
        return 0
    result = db.execute(
        delete(Repository).where(
            Repository.installation_id == installation_id,
            Repository.id.in_(repo_ids),
        ),
        execution_options={"synchronize_session": "fetch"},
    )
    return int(getattr(result, "rowcount", 0) or 0)


def repository_by_id(db: DbSession, repo_id: int) -> Repository | None:
    """One repository by GitHub id, unscoped.

    Unscoped because its only caller is the webhook handler, which is authorised by an HMAC over
    the request body rather than by a session. Never call this on a user-facing path: `D-035`
    requires those to filter by the session's installation ids, and `list_repositories` and
    `set_analysis_enabled` are the functions that do.
    """
    return db.execute(select(Repository).where(Repository.id == repo_id)).scalar_one_or_none()


def ensure_installation(
    db: DbSession,
    installation_id: int,
    account_login: str,
    account_type: str,
) -> None:
    """Record an installation if it is not already known. Never overwrites an existing row.

    The webhook path uses this rather than `upsert_installation` for one specific reason: a
    `pull_request` payload carries only the installation's id, so the account details are inferred
    from the repository owner and `suspended_at` is not present at all. An upsert would therefore
    clear a suspension every time somebody pushed to a PR. Only the `installation` event itself
    knows an installation's real state, and only it may write one.
    """
    db.execute(
        pg_insert(Installation)
        .values(id=installation_id, account_login=account_login, account_type=account_type)
        .on_conflict_do_nothing(index_elements=[Installation.id])
    )


def ensure_repository(
    db: DbSession,
    repo_id: int,
    installation_id: int,
    full_name: str,
    is_private: bool,
) -> None:
    """Record a repository if it is not already known. Never overwrites an existing row.

    For the installation events, whose repository objects carry no `default_branch` — so a new row
    takes the column default and a later sign-in sync corrects it. Writing a guessed branch over a
    known one would be worse than leaving the placeholder where it can be seen.
    """
    db.execute(
        pg_insert(Repository)
        .values(
            id=repo_id,
            installation_id=installation_id,
            full_name=full_name,
            is_private=is_private,
        )
        .on_conflict_do_nothing(index_elements=[Repository.id])
    )
