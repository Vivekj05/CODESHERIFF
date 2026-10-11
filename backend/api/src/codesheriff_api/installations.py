"""The GitHub App page's one read: which installations this caller has connected (D-102).

Read from the database, never from GitHub. The `installation` and `installation_repositories`
webhooks keep these rows current, and the page has nothing to ask GitHub that they do not already
say. Every GitHub action on the page (install, manage, disconnect) is a link to GitHub's own
settings, so no endpoint here can change an installation.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter
from pydantic import BaseModel

from codesheriff_api.config import ApiConfig
from codesheriff_api.deps import ConfigDep, DbDep, SessionDep
from codesheriff_storage import InstallationSummary, list_installations

router = APIRouter(prefix="/installations", tags=["installations"])


class InstallationOut(BaseModel):
    id: int
    account_login: str
    account_type: str
    suspended: bool
    repository_count: int
    connected_at: datetime
    manage_url: str
    """GitHub's settings page for this installation: change repositories, suspend, or uninstall."""


class InstallationList(BaseModel):
    items: list[InstallationOut]
    install_url: str | None
    """Where to install the App on another account, if the App's slug is configured."""


def manage_url(config: ApiConfig, item: InstallationSummary) -> str:
    """A user's installations live under their settings; an organisation's under the org's."""
    web = config.github_web_base.rstrip("/")
    if item.account_type == "Organization":
        return f"{web}/organizations/{item.account_login}/settings/installations/{item.id}"
    return f"{web}/settings/installations/{item.id}"


@router.get("", response_model=InstallationList)
def read_installations(config: ConfigDep, db: DbDep, session: SessionDep) -> InstallationList:
    """This caller's connected installations. Empty when they have connected none (D-035)."""
    items = list_installations(db, list(session.visible_installation_ids))
    return InstallationList(
        items=[
            InstallationOut(
                id=item.id,
                account_login=item.account_login,
                account_type=item.account_type,
                suspended=item.suspended,
                repository_count=item.repository_count,
                connected_at=item.connected_at,
                manage_url=manage_url(config, item),
            )
            for item in items
        ],
        install_url=config.install_url,
    )
