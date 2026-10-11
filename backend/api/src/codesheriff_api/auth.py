"""Who the caller is, and the App installation round trip.

Sign-in itself no longer happens here. Better Auth runs it in the dashboard (D-101) and hands this
API a signed JWT; `deps.get_current_principal` verifies it. What remains on this side:

- `GET /auth/session` reports the verified caller, and makes sure every installation in their
  token has rows here. The token is GitHub's answer about what the user can see (D-035); the rows
  are what the repository list and the audit queries join against. Installations are read as the
  App, never with the user's token, which this process never holds.
- `GET /auth/install` and its callback send the user to GitHub to install the App and back.

**Why the install callback still grants nothing.** GitHub sends the user back with
`?installation_id=...`, which is attacker-supplied: anyone can request this URL with somebody
else's id. So it is logged and ignored, and the user is sent to sign in again, which re-reads the
installation list from GitHub. There is no path where a URL parameter widens what a token can see.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from codesheriff_api.config import ApiConfig, MissingCredentialError
from codesheriff_api.deps import ConfigDep, DbDep, GitHubDep, SessionDep
from codesheriff_api.github_gateway import GitHubError, GitHubGateway
from codesheriff_storage import Installation, upsert_installation, upsert_repository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


class SessionInfo(BaseModel):
    """What the dashboard needs to render a signed-in shell."""

    login: str
    name: str | None
    avatar_url: str | None
    installation_count: int
    expires_at: str
    install_url: str | None


def _dashboard_url(config: ApiConfig, path: str) -> str:
    return f"{config.dashboard_origin.rstrip('/')}{path}"


def sync_installations(db: DbSession, github: GitHubGateway, installation_ids: list[int]) -> int:
    """Create rows for installations in a token that this database has not seen. Returns how many.

    Only the missing ones. The `installation` and `installation_repositories` webhooks keep known
    installations current, so re-reading every installation on every page load would spend the
    App's rate limit to learn nothing. One installation failing does not fail the request: a
    suspended or just-removed installation is a normal state, not an authentication error.
    """
    if not installation_ids:
        return 0
    known = set(
        db.execute(select(Installation.id).where(Installation.id.in_(installation_ids))).scalars()
    )
    synced = 0
    for installation_id in installation_ids:
        if installation_id in known:
            continue
        try:
            account = github.get_installation(installation_id)
            upsert_installation(
                db,
                installation_id=account.installation_id,
                account_login=account.account_login,
                account_type=account.account_type,
            )
            for repo in github.list_installation_repositories(installation_id):
                upsert_repository(
                    db,
                    repo_id=repo.repo_id,
                    installation_id=installation_id,
                    full_name=repo.full_name,
                    default_branch=repo.default_branch,
                    is_private=repo.is_private,
                )
            synced += 1
        except (GitHubError, MissingCredentialError) as exc:
            logger.warning("Could not sync installation %s: %s", installation_id, exc)
    return synced


@router.get("/session", response_model=SessionInfo)
def read_session(
    config: ConfigDep, db: DbDep, github: GitHubDep, session: SessionDep
) -> SessionInfo:
    """Who the caller is. 401 when the token is absent, forged, expired or malformed."""
    sync_installations(db, github, list(session.visible_installation_ids))
    return SessionInfo(
        login=session.login,
        name=session.name,
        avatar_url=session.avatar_url,
        installation_count=len(session.visible_installation_ids),
        expires_at=session.expires_at.isoformat(),
        install_url=config.install_url,
    )


@router.get("/install")
def install(config: ConfigDep) -> RedirectResponse:
    """Send the user to GitHub to install the App on an account."""
    if not config.install_url:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="GITHUB_APP_SLUG is not set, so the installation URL cannot be built.",
        )
    return RedirectResponse(url=config.install_url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)


@router.get("/install/callback")
def install_callback(
    config: ConfigDep,
    installation_id: int | None = Query(default=None),
    setup_action: str | None = Query(default=None),
) -> RedirectResponse:
    """GitHub's post-installation redirect. Grants nothing; re-derives everything.

    `installation_id` arrives in a URL the user controls, so it is logged and otherwise ignored.
    Sending the user back through sign-in makes GitHub the authority on which installations they
    can see, which is the only source an address bar cannot forge.
    """
    logger.info(
        "Installation callback: installation_id=%s setup_action=%s (re-deriving via sign-in)",
        installation_id,
        setup_action,
    )
    return RedirectResponse(
        url=_dashboard_url(config, "/sign-in?next=/repositories"),
        status_code=status.HTTP_303_SEE_OTHER,
    )
