"""Sign-in, sign-out, and the App installation round trip.

The whole flow lives on this side of the wire. §6 makes the dashboard a rendering layer: it holds
no client secret, exchanges no code, and never talks to GitHub. It sends the browser here and reads
the result.

**How access is decided.** At sign-in the user's OAuth token is spent on two reads — who they are,
and which installations of this App they can see — and then discarded (D-036). That list is stored
on the session and is the only thing that scopes later queries (D-035). No ACL is kept, and nothing
in the database can be replayed against GitHub.

**Why the install callback does not grant anything.** GitHub sends the user back from an
installation with `?installation_id=...` in the URL, which is attacker-supplied data: anyone could
request this endpoint with somebody else's installation id. So it grants no visibility at all. It
redirects into the OAuth flow, which re-derives the whole list from GitHub. For a user who has
already authorised the App that redirect is silent, so the cost is one hop and the gain is that
there is no path where a URL parameter widens what a session can see.
"""

from __future__ import annotations

import logging
import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession

from codesheriff_api.config import ApiConfig, MissingCredentialError
from codesheriff_api.deps import ConfigDep, DbDep, GitHubDep, SessionDep
from codesheriff_api.github_gateway import GitHubError, GitHubGateway, GitHubIdentity
from codesheriff_storage import (
    create_session,
    revoke_session,
    upsert_installation,
    upsert_repository,
    upsert_user,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

STATE_COOKIE = "codesheriff_oauth_state"
NEXT_COOKIE = "codesheriff_oauth_next"
STATE_TTL_SECONDS = 600
"""Two cookies rather than one packed value.

A path contains `/`, which is outside `http.cookies`' set of legal unquoted characters, so packing
the two together makes the whole value quoted. It round-trips correctly — but the state comparison
is the CSRF check, and it should compare a raw random token with no encoding step in the middle
that a future change could get wrong.
"""


class SessionInfo(BaseModel):
    """What the dashboard needs to render a signed-in shell."""

    login: str
    name: str | None
    avatar_url: str | None
    installation_count: int
    expires_at: str
    install_url: str | None


def safe_next_path(candidate: str | None) -> str:
    """Reduce a `next` parameter to a same-origin path, or `/repositories`.

    A redirect target taken from a query string is an open redirect unless it is constrained to a
    path. `//evil.example` is the case that catches people: it has no scheme, passes a naive
    `startswith("/")` check, and is treated as protocol-relative by every browser.
    """
    if not candidate or not candidate.startswith("/") or candidate.startswith("//"):
        return "/repositories"
    return candidate


def _dashboard_url(config: ApiConfig, path: str) -> str:
    return f"{config.dashboard_origin.rstrip('/')}{path}"


@router.get("/login")
def login(
    config: ConfigDep,
    next: str = Query(default="/repositories"),
) -> RedirectResponse:
    """Start the OAuth web flow.

    The `state` parameter is generated here, sent to GitHub, and simultaneously stored in a
    short-lived `HttpOnly` cookie. On the way back the two must match: without that check, an
    attacker can complete a flow they started and land the victim's browser on a session that is
    not the victim's (CSRF on login).
    """
    try:
        oauth = config.require_oauth_app()
    except MissingCredentialError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc

    state = secrets.token_urlsafe(24)
    target = safe_next_path(next)

    query = urlencode(
        {
            "client_id": oauth.client_id,
            "redirect_uri": config.oauth_redirect_uri,
            "state": state,
        }
    )
    response = RedirectResponse(
        url=f"{config.github_web_base.rstrip('/')}/login/oauth/authorize?{query}",
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )
    for name, value in ((STATE_COOKIE, state), (NEXT_COOKIE, target)):
        response.set_cookie(
            name,
            value,
            max_age=STATE_TTL_SECONDS,
            httponly=True,
            secure=config.session_cookie_secure,
            samesite="lax",
            path="/",
        )
    return response


def _sync_installations(db: DbSession, github: GitHubGateway, identity: GitHubIdentity) -> None:
    """Refresh installation and repository rows for everything this user can see.

    Done at sign-in rather than on demand so the repository list is a plain database query — the
    dashboard scrolls it, and paging through it via GitHub would spend the installation's rate
    limit on every scroll. Chapter 6's `installation` and `installation_repositories` webhooks keep
    it fresh between sign-ins.

    One installation failing does not fail the sign-in. A suspended or newly uninstalled
    installation is a normal state, not an authentication error.
    """
    for installation_id in identity.installation_ids:
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
        except GitHubError as exc:
            logger.warning("Skipping installation %s during sign-in: %s", installation_id, exc)


@router.get("/callback")
def callback(
    request: Request,
    config: ConfigDep,
    db: DbDep,
    github: GitHubDep,
    code: str = Query(default=""),
    state: str = Query(default=""),
) -> RedirectResponse:
    """Finish the OAuth web flow: verify state, exchange the code, open a session."""
    expected_state = request.cookies.get(STATE_COOKIE, "")
    next_path = request.cookies.get(NEXT_COOKIE, "")

    if (
        not code
        or not state
        or not expected_state
        or not secrets.compare_digest(state, expected_state)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="OAuth state did not match. Start again from the sign-in page.",
        )

    try:
        identity = github.sign_in(code)
    except MissingCredentialError as exc:
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail=str(exc)) from exc
    except GitHubError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="GitHub rejected the sign-in."
        ) from exc

    user = upsert_user(
        db,
        github_id=identity.github_id,
        login=identity.login,
        name=identity.name,
        avatar_url=identity.avatar_url,
    )
    _sync_installations(db, github, identity)
    _, token = create_session(
        db,
        user_id=user.id,
        visible_installation_ids=identity.installation_ids,
        ttl=config.session_ttl,
    )

    response = RedirectResponse(
        url=_dashboard_url(config, safe_next_path(next_path)),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.set_cookie(
        config.session_cookie_name,
        token,
        max_age=int(config.session_ttl.total_seconds()),
        httponly=True,
        secure=config.session_cookie_secure,
        samesite="lax",
        path="/",
    )
    response.delete_cookie(STATE_COOKIE, path="/")
    response.delete_cookie(NEXT_COOKIE, path="/")
    return response


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
    The redirect into `/auth/login` makes GitHub the authority on which installations this user can
    see, which is the only source that cannot be forged by editing an address bar.
    """
    logger.info(
        "Installation callback: installation_id=%s setup_action=%s (re-deriving via OAuth)",
        installation_id,
        setup_action,
    )
    return RedirectResponse(
        url=f"{config.api_public_url.rstrip('/')}/auth/login?next=/repositories",
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/session", response_model=SessionInfo)
def read_session(config: ConfigDep, session: SessionDep) -> SessionInfo:
    """Who the caller is. 401 when the cookie is absent, unknown, revoked or expired."""
    return SessionInfo(
        login=session.user.login,
        name=session.user.name,
        avatar_url=session.user.avatar_url,
        installation_count=len(session.visible_installation_ids),
        expires_at=session.expires_at.isoformat(),
        install_url=config.install_url,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, config: ConfigDep, db: DbDep) -> Response:
    """Revoke the session server-side and clear the cookie.

    Server-side revocation is the reason sessions are rows rather than signed tokens: clearing a
    cookie only asks the browser to forget, and a copy taken beforehand would still work.
    """
    token = request.cookies.get(config.session_cookie_name, "")
    revoked = revoke_session(db, token)
    logger.info("Logout: %s", "session revoked" if revoked else "no live session")

    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    result.delete_cookie(config.session_cookie_name, path="/")
    return result
