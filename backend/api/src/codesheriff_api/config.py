"""API configuration.

Secrets are read from the environment only (§6): the App private key and the webhook secret never
appear in a file this repository tracks. The OAuth client secret is no longer the API's: sign-in
runs in the dashboard under Better Auth (D-101), and this process only verifies the tokens it signs.

Nothing here raises at import time. `/health` has to answer on a machine with no GitHub App
registered — otherwise the first thing a new contributor sees is a stack trace about a `.pem` they
were never told to create. The credentials are validated at the point of use, by
`require_oauth_app()` and `require_github_app()`, which fail with a message naming the missing
variable.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MissingCredentialError(RuntimeError):
    """A GitHub credential the requested operation needs is not configured."""


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
    github_app_private_key_path: str | None = Field(
        default=None, alias="GITHUB_APP_PRIVATE_KEY_PATH"
    )

    github_app_slug: str | None = Field(default=None, alias="GITHUB_APP_SLUG")
    """The App's URL slug, used to build the install link. From the App's settings page."""

    github_webhook_secret: str | None = Field(default=None, alias="GITHUB_WEBHOOK_SECRET")
    """The shared secret GitHub signs each delivery with. Without it the webhook refuses every
    request rather than accepting unsigned ones — an unauthenticated endpoint here lets anyone who
    learns the URL drive analysis and post comments under the App's identity (`AUDIT.md` 0.1)."""

    celery_broker_url: str = Field(default="redis://localhost:6379/0", alias="CELERY_BROKER_URL")
    """Where the audit is handed to the worker. The API only ever writes to this."""

    audit_queue_name: str = Field(default="audits", alias="AUDIT_QUEUE_NAME")

    enqueue_timeout_seconds: float = 2.0
    """A cap on the broker call, not a general timeout. GitHub abandons a delivery at 10s and this
    endpoint is budgeted at under 3s, so a Redis that has stopped answering must fail the request
    quickly enough that GitHub's own retry is what recovers it."""

    github_api_base: str = "https://api.github.com"
    github_web_base: str = "https://github.com"

    api_public_url: str = Field(default="http://localhost:8000", alias="API_PUBLIC_URL")
    """This API's own public address."""

    dashboard_origin: str = Field(default="http://localhost:3000", alias="DASHBOARD_ORIGIN")
    """The single browser origin allowed to call this API."""

    better_auth_url: str = Field(default="http://localhost:3000", alias="BETTER_AUTH_URL")
    """Where Better Auth runs (the dashboard). Its JWKS is fetched from here, and its origin is the
    issuer and audience every token must carry (D-101)."""

    jwks_cache_seconds: int = 300
    """How long fetched signing keys are reused. A token signed by a key not in the cache triggers
    one refetch, so a rotated key is picked up without waiting for this to lapse."""

    @property
    def jwks_url(self) -> str:
        return f"{self.better_auth_url.rstrip('/')}/api/auth/jwks"

    @property
    def token_issuer(self) -> str:
        """Better Auth's default `iss` and `aud`: the origin of its base URL."""
        parts = urlsplit(self.better_auth_url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def install_url(self) -> str | None:
        """Where to send a user to install the App, if the slug is configured."""
        if not self.github_app_slug:
            return None
        return f"{self.github_web_base.rstrip('/')}/apps/{self.github_app_slug}/installations/new"

    def require_webhook_secret(self) -> str:
        """The webhook signing secret, or a clear failure naming what is missing.

        Deliberately not defaulted to an empty string. A falsy secret would make
        `hmac.compare_digest` compare against a signature of the empty key, which an attacker can
        compute — a missing secret has to stop the request, never weaken the check.
        """
        if not self.github_webhook_secret:
            raise MissingCredentialError(
                "GITHUB_WEBHOOK_SECRET must be set to receive webhooks. It is the value entered "
                "in the GitHub App's webhook settings; see .env.example."
            )
        return self.github_webhook_secret

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
