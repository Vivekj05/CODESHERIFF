"""Users, sessions, installations and repository rows — every query the API needs for sign-in.

Queries live here rather than in `apps/api` so the app layer holds routes and GitHub calls, and
this package holds SQL. The split matters for one specific reason: the session lookup below is the
only thing standing between a cookie and someone else's data, and it is easier to keep correct in
one audited place than spread across route handlers.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session as DbSession

from codesheriff_storage.models import Installation, Repository, Session, User

SESSION_TOKEN_BYTES = 32
"""256 bits from `secrets.token_urlsafe`. The cookie value; never stored."""


def hash_session_token(token: str) -> str:
    """SHA-256 of a session token.

    Plain SHA-256 rather than a password hash on purpose: the token is 256 random bits, not a
    human-chosen secret, so there is nothing for a slow KDF to defend against. What matters is that
    the database holds a one-way image of it (D-036).
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def upsert_user(
    db: DbSession,
    github_id: int,
    login: str,
    name: str | None,
    avatar_url: str | None,
) -> User:
    """Insert or refresh a user from their GitHub identity, and stamp the login time."""
    now = datetime.now(UTC)
    stmt = (
        pg_insert(User)
        .values(
            id=github_id,
            login=login,
            name=name,
            avatar_url=avatar_url,
            last_login_at=now,
        )
        .on_conflict_do_update(
            index_elements=[User.id],
            set_={
                "login": login,
                "name": name,
                "avatar_url": avatar_url,
                "last_login_at": now,
                "updated_at": now,
            },
        )
        .returning(User)
    )
    # populate_existing, because RETURNING alone does not refresh an instance the identity map is
    # already holding: a second sign-in in one session would hand back the previous login.
    user = db.execute(stmt, execution_options={"populate_existing": True}).scalar_one()
    return user


def create_session(
    db: DbSession,
    user_id: int,
    visible_installation_ids: list[int],
    ttl: timedelta,
) -> tuple[Session, str]:
    """Open a session. Returns the row and the **plaintext token**, which is never stored.

    The token is returned exactly once, to be set as a cookie by the caller. There is no way to
    recover it afterwards — which is the point.
    """
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    now = datetime.now(UTC)
    row = Session(
        user_id=user_id,
        token_sha256=hash_session_token(token),
        visible_installation_ids=list(visible_installation_ids),
        expires_at=now + ttl,
        last_seen_at=now,
    )
    db.add(row)
    db.flush()
    return row, token


def session_for_token(db: DbSession, token: str) -> Session | None:
    """Resolve a cookie value to a live session, or None.

    Returns None for an unknown, revoked or expired token — the caller cannot tell which, and does
    not need to. Expiry is checked in SQL against `now()` rather than in Python so a clock-skewed
    application server cannot extend a session.
    """
    if not token:
        return None
    stmt = select(Session).where(
        Session.token_sha256 == hash_session_token(token),
        Session.revoked_at.is_(None),
        Session.expires_at > datetime.now(UTC),
    )
    return db.execute(stmt).scalar_one_or_none()


def touch_session(db: DbSession, session_id: object) -> None:
    """Record activity. Does not extend expiry — a session's lifetime is fixed at creation.

    `ck_sessions_expiry_after_creation` enforces that from the database side: an expiry cannot be
    moved before the row was created. Ending a session early is `revoke_session`, which is visible
    as a revocation rather than indistinguishable from a short-lived session.
    """
    db.execute(
        update(Session).where(Session.id == session_id).values(last_seen_at=datetime.now(UTC))
    )


def revoke_session(db: DbSession, token: str) -> bool:
    """Revoke by token. Returns whether a live session was found."""
    row = session_for_token(db, token)
    if row is None:
        return False
    row.revoked_at = datetime.now(UTC)
    db.flush()
    return True


def purge_expired_sessions(db: DbSession) -> int:
    """Delete sessions that expired more than a day ago. Returns the number removed.

    `synchronize_session="fetch"` so the deleted rows are also evicted from the session's identity
    map. Without it a caller that still holds one of those objects keeps reading it as though it
    were live — a purge that leaves live-looking sessions behind in memory is worse than no purge.
    """
    cutoff = datetime.now(UTC) - timedelta(days=1)
    result = db.execute(
        delete(Session).where(Session.expires_at < cutoff),
        execution_options={"synchronize_session": "fetch"},
    )
    # `Result` is the general type; only the cursor result carries rowcount, and a DELETE always
    # produces one.
    return int(getattr(result, "rowcount", 0) or 0)


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
