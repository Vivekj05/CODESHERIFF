"""API configuration.

Secrets are read from the environment only (§6): the App private key, the OAuth client secret and
the webhook secret never appear in a file this repository tracks.

Nothing here raises at import time. `/health` has to answer on a machine with no GitHub App
registered — otherwise the first thing a new contributor sees is a stack trace about a `.pem` they
were never told to create. The credentials are validated at the point of use, by
`require_oauth_app()` and `require_github_app()`, which fail with a message naming the missing
variable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MissingCredentialError(RuntimeError):
    """A GitHub credential the requested operation needs is not configured."""


@dataclass(frozen=True)
class OAuthApp:
    """The client credentials for the user-facing OAuth web flow."""

    client_id: str
    client_secret: str


@dataclass(frozen=True)
class GitHubApp:
    """The App identity used to mint installation tokens."""

    app_id: str
    private_key: str


class ApiConfig(BaseSettings):
    """Everything the edge needs. No analysis settings — that is the worker's business."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    github_app_id: str | None = Field(default=None, alias="GITHUB_APP_ID")
    github_app_client_id: str | None = Field(default=None, alias="GITHUB_APP_CLIENT_ID")
    github_app_client_secret: str | None = Field(default=None, alias="GITHUB_APP_CLIENT_SECRET")
    github_app_private_key_path: str | None = Field(
        default=None, alias="GITHUB_APP_PRIVATE_KEY_PATH"
    )

    github_app_slug: str | None = Field(default=None, alias="GITHUB_APP_SLUG")
    """The App's URL slug, used to build the install link. From the App's settings page."""

    github_api_base: str = "https://api.github.com"
    github_web_base: str = "https://github.com"

    api_public_url: str = Field(default="http://localhost:8000", alias="API_PUBLIC_URL")
    """Where GitHub sends the user back. Must match the App's callback URL exactly."""

    dashboard_origin: str = Field(default="http://localhost:3000", alias="DASHBOARD_ORIGIN")
    """The single browser origin allowed to call this API with credentials."""

    session_ttl_hours: int = 8
    """Fixed at creation and never extended. Access is a snapshot taken at sign-in (D-035), so a
    long session is a long-lived stale answer."""

    session_cookie_name: str = "codesheriff_session"

    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")
    """False for `http://localhost` development. **Must be true in any deployment** — a session
    cookie sent over plain HTTP is a session anybody on the path can take."""

    @property
    def session_ttl(self) -> timedelta:
        return timedelta(hours=self.session_ttl_hours)

    @property
    def oauth_redirect_uri(self) -> str:
        return f"{self.api_public_url.rstrip('/')}/auth/callback"

    @property
    def install_url(self) -> str | None:
        """Where to send a user to install the App, if the slug is configured."""
        if not self.github_app_slug:
            return None
        return f"{self.github_web_base.rstrip('/')}/apps/{self.github_app_slug}/installations/new"

    def require_oauth_app(self) -> OAuthApp:
        """The OAuth client credentials, or a clear failure naming what is missing."""
        if not self.github_app_client_id or not self.github_app_client_secret:
            raise MissingCredentialError(
                "GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET must be set to sign in. "
                "Both come from the GitHub App's settings page; see .env.example."
            )
        return OAuthApp(
            client_id=self.github_app_client_id,
            client_secret=self.github_app_client_secret,
        )

    def require_github_app(self) -> GitHubApp:
        """The App id and private key, or a clear failure naming what is missing.

        The key is read from disk on each call rather than cached in the process. It is a
        credential; keeping it in a long-lived attribute means it appears in every heap dump and
        every crash report for the lifetime of the process.
        """
        if not self.github_app_id:
            raise MissingCredentialError("GITHUB_APP_ID must be set to talk to GitHub as the App.")
        if not self.github_app_private_key_path:
            raise MissingCredentialError(
                "GITHUB_APP_PRIVATE_KEY_PATH must point at the App's .pem private key. "
                "Keep the file outside this repository."
            )
        key_path = Path(self.github_app_private_key_path)
        if not key_path.is_file():
            raise MissingCredentialError(
                f"GITHUB_APP_PRIVATE_KEY_PATH points at {key_path}, which does not exist."
            )
        return GitHubApp(app_id=self.github_app_id, private_key=key_path.read_text())

    @classmethod
    def load(cls) -> ApiConfig:
        return cls()
