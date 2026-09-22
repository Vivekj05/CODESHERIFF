"""Repository listing and the analysis toggle.

Reads come from the database, not from GitHub: the list is refreshed at sign-in and, from Chapter 6,
by `installation_repositories` webhooks. Paging through GitHub on every scroll would spend an
installation's rate limit on a UI gesture.

Every query is scoped by the session's installation snapshot (D-035). The scoping lives in
`codesheriff_storage.identity`, one layer down, so a route cannot forget it by omitting a filter.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from codesheriff_api.deps import DbDep, SessionDep
from codesheriff_storage import list_repositories, set_analysis_enabled

router = APIRouter(prefix="/repositories", tags=["repositories"])

MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 30


class RepositoryOut(BaseModel):
    id: int
    full_name: str
    default_branch: str
    is_private: bool
    analysis_enabled: bool


class RepositoryPage(BaseModel):
    """One page of repositories, plus the cursor for the next.

    `next_cursor` is the last `full_name` on the page rather than an offset. The dashboard scrolls
    this list, and an offset page silently skips or repeats rows when an installation event inserts
    a repository above the cursor mid-scroll.
    """

    items: list[RepositoryOut]
    next_cursor: str | None


class AnalysisToggle(BaseModel):
    analysis_enabled: bool


@router.get("", response_model=RepositoryPage)
def list_repos(
    db: DbDep,
    session: SessionDep,
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    cursor: str | None = Query(default=None),
) -> RepositoryPage:
    """Repositories visible to this session, ordered by full name."""
    rows = list_repositories(
        db,
        installation_ids=list(session.visible_installation_ids),
        limit=limit,
        after_full_name=cursor,
    )
    items = [
        RepositoryOut(
            id=row.id,
            full_name=row.full_name,
            default_branch=row.default_branch,
            is_private=row.is_private,
            analysis_enabled=row.analysis_enabled,
        )
        for row in rows
    ]
    # A full page implies there may be more; a short page is the end. One extra request at the end
    # of a scroll is cheaper than a count query on every page.
    next_cursor = items[-1].full_name if len(items) == limit else None
    return RepositoryPage(items=items, next_cursor=next_cursor)


@router.patch("/{repo_id}", response_model=RepositoryOut)
def toggle_analysis(
    repo_id: int,
    payload: AnalysisToggle,
    db: DbDep,
    session: SessionDep,
) -> RepositoryOut:
    """Turn analysis on or off for one repository.

    This is what "connect" and "disconnect" mean here. Removing the App itself is done on GitHub —
    an API that could uninstall itself would need write access to the installation, which is not
    among the permissions this App requests (D-034).

    404 covers both "no such repository" and "not yours". Distinguishing them would confirm the
    existence of a repository the caller cannot see.
    """
    row = set_analysis_enabled(
        db,
        repo_id=repo_id,
        installation_ids=list(session.visible_installation_ids),
        enabled=payload.analysis_enabled,
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Repository not found.")
    return RepositoryOut(
        id=row.id,
        full_name=row.full_name,
        default_branch=row.default_branch,
        is_private=row.is_private,
        analysis_enabled=row.analysis_enabled,
    )
