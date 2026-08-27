"""Every GitHub call the edge makes, behind one Protocol.

Two reasons it is a Protocol rather than four functions.

**Tests must never make live API calls** (CLAUDE.md). `FakeGitHubGateway` in the test suite
implements this interface, so the routes are exercised without a network stack at all — not mocked
at the HTTP layer, where a typo in a URL still passes.

**The OAuth token never escapes this module.** `sign_in` takes the authorisation code and returns
identity plus visible installations. There is no method that hands a caller a token, which is what
makes "no GitHub credential is stored" (D-036) a property of the interface rather than a habit.

Synchronous by design, matching D-028: FastAPI runs `def` handlers in a threadpool, so a sync
GitHub client and a sync database session compose without an async/sync boundary in the middle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
from githubkit import AppAuthStrategy, BaseAuthStrategy, GitHub, OAuthWebAuthStrategy

from codesheriff_api.config import ApiConfig


class GitHubError(RuntimeError):
    """GitHub refused or could not answer. Carries no token material."""


@dataclass(frozen=True)
class GitHubIdentity:
    """Who signed in, and what they can see."""

    github_id: int
    login: str
    name: str | None
    avatar_url: str | None
    installation_ids: list[int] = field(default_factory=list)


@dataclass(frozen=True)
class InstallationAccount:
    installation_id: int
    account_login: str
    account_type: str


@dataclass(frozen=True)
class InstallationRepository:
    repo_id: int
    full_name: str
    default_branch: str
    is_private: bool


class GitHubGateway(Protocol):
    """The four calls Chapter 5 needs."""

    def sign_in(self, code: str) -> GitHubIdentity:
        """Exchange an OAuth web-flow code for identity and visible installations."""
        ...

    def get_installation(self, installation_id: int) -> InstallationAccount:
        """Read one installation as the App."""
        ...

    def list_installation_repositories(self, installation_id: int) -> list[InstallationRepository]:
        """Every repository an installation grants access to."""
        ...


class GitHubKitGateway:
    """The real implementation, on `githubkit`.

    `transport` exists for tests that want to drive this class itself rather than substitute a fake
    — an httpx `MockTransport` keeps even those offline.
    """

    def __init__(self, config: ApiConfig, transport: httpx.BaseTransport | None = None) -> None:
        self._config = config
        self._transport = transport

    def _client(self, auth: BaseAuthStrategy) -> GitHub[Any]:
        return GitHub(
            auth,
            base_url=self._config.github_api_base,
            transport=self._transport,
            user_agent="CodeSheriff",
        )

    def sign_in(self, code: str) -> GitHubIdentity:
        """Exchange the code, then immediately spend the token on two reads and drop it.

        `githubkit` performs the exchange inside the auth strategy, so the access token is never
        assigned to a name in this codebase — and the client goes out of scope when this method
        returns.
        """
        oauth = self._config.require_oauth_app()
        strategy = OAuthWebAuthStrategy(
            oauth.client_id,
            oauth.client_secret,
            code,
            redirect_uri=self._config.oauth_redirect_uri,
        )
        try:
            with self._client(strategy) as github:
                user = github.rest.users.get_authenticated().parsed_data
                installations = github.rest.apps.list_installations_for_authenticated_user(
                    per_page=100
                ).parsed_data.installations
                return GitHubIdentity(
                    github_id=int(user.id),
                    login=str(user.login),
                    name=getattr(user, "name", None),
                    avatar_url=getattr(user, "avatar_url", None),
                    installation_ids=[int(item.id) for item in installations],
                )
        except Exception as exc:
            raise GitHubError(f"GitHub sign-in failed: {type(exc).__name__}") from exc

    def _as_installation(self, installation_id: int) -> BaseAuthStrategy:
        app = self._config.require_github_app()
        return AppAuthStrategy(app.app_id, app.private_key).as_installation(installation_id)

    def get_installation(self, installation_id: int) -> InstallationAccount:
        app = self._config.require_github_app()
        try:
            with self._client(AppAuthStrategy(app.app_id, app.private_key)) as github:
                data = github.rest.apps.get_installation(installation_id).parsed_data
                account = data.account
                return InstallationAccount(
                    installation_id=int(data.id),
                    account_login=str(getattr(account, "login", "") or ""),
                    account_type=str(getattr(account, "type", "User") or "User"),
                )
        except Exception as exc:
            raise GitHubError(
                f"Could not read installation {installation_id}: {type(exc).__name__}"
            ) from exc

    def list_installation_repositories(self, installation_id: int) -> list[InstallationRepository]:
        try:
            with self._client(self._as_installation(installation_id)) as github:
                repositories: list[InstallationRepository] = []
                page = 1
                while True:
                    response = github.rest.apps.list_repos_accessible_to_installation(
                        per_page=100, page=page
                    ).parsed_data
                    batch = response.repositories
                    for repo in batch:
                        repositories.append(
                            InstallationRepository(
                                repo_id=int(repo.id),
                                full_name=str(repo.full_name),
                                default_branch=str(repo.default_branch or "main"),
                                is_private=bool(repo.private),
                            )
                        )
                    # GitHub caps per_page at 100; stop on a short page rather than trusting
                    # total_count, which counts repositories the token may not actually reach.
                    if len(batch) < 100:
                        return repositories
                    page += 1
        except GitHubError:
            raise
        except Exception as exc:
            raise GitHubError(
                f"Could not list repositories for installation {installation_id}: "
                f"{type(exc).__name__}"
            ) from exc
