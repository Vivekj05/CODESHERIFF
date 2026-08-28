"""Worker configuration.

Deliberately its own settings object rather than a shared one with `apps/api` (D-042). The two
processes need overlapping but different credentials, and the overlap is not worth the cost of the
union: the API would end up holding an LLM key it must never need, and this process would hold the
OAuth client secret and the webhook signing secret, neither of which it can use. Each process
loading only what it can use is what keeps the blast radius of either one small.

What is shared is the *App identity* — both mint tokens for the same GitHub App — and that is
shared as configuration values in the environment, not as a Python object.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MissingCredentialError(RuntimeError):
    """A credential the requested operation needs is not configured."""


@dataclass(frozen=True)
class GitHubApp:
    """The App identity used to mint installation tokens."""

    app_id: str
    private_key: str


class WorkerConfig(BaseSettings):
    """Everything the pipeline needs. No OAuth client secret, no webhook secret."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    github_app_id: str | None = Field(default=None, alias="GITHUB_APP_ID")
    github_app_private_key_path: str | None = Field(
        default=None, alias="GITHUB_APP_PRIVATE_KEY_PATH"
    )
    github_api_base: str = "https://api.github.com"

    celery_broker_url: str = Field(default="redis://localhost:6379/0", alias="CELERY_BROKER_URL")
    audit_queue_name: str = Field(default="audits", alias="AUDIT_QUEUE_NAME")

    dashboard_base_url: str = Field(default="http://localhost:3000", alias="DASHBOARD_ORIGIN")
    """Where the PR comment points for detail. The comment is a summary; the dashboard is where a
    finding is explained (D-034)."""

    def require_github_app(self) -> GitHubApp:
        """The App id and private key, or a clear failure naming what is missing.

        Read from disk on each call rather than cached on the instance. It is a credential, and a
        long-lived attribute puts it in every heap dump and crash report for the life of the
        process — which for a worker is measured in days.
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
    def load(cls) -> WorkerConfig:
        return cls()
