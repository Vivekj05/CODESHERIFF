"""Configuration and URL handling. No database, no network, no skips."""

from __future__ import annotations

import pytest

from codesheriff_api.config import ApiConfig, MissingCredentialError


def test_health_config_loads_without_any_github_credentials() -> None:
    """A machine with no App registered must still be able to start the API.

    Otherwise the first thing a new contributor meets is a stack trace about a `.pem` nobody told
    them to create.
    """
    config = ApiConfig(_env_file=None)  # type: ignore[call-arg]
    assert config.github_app_id is None
    assert config.install_url is None


def test_missing_private_key_path_is_reported_before_a_read() -> None:
    config = ApiConfig(_env_file=None, GITHUB_APP_ID="1")  # type: ignore[call-arg]
    with pytest.raises(MissingCredentialError, match="GITHUB_APP_PRIVATE_KEY_PATH"):
        config.require_github_app()


def test_nonexistent_private_key_is_reported_with_its_path(tmp_path: object) -> None:
    missing = f"{tmp_path}/nope.pem"
    config = ApiConfig(  # type: ignore[call-arg]
        _env_file=None,
        GITHUB_APP_ID="1",
        GITHUB_APP_PRIVATE_KEY_PATH=missing,
    )
    with pytest.raises(MissingCredentialError, match="does not exist"):
        config.require_github_app()


def test_private_key_is_read_from_disk_not_cached(tmp_path: object) -> None:
    """Read per call, so the key does not sit in the process for its whole lifetime."""
    from pathlib import Path

    key_file = Path(str(tmp_path)) / "app.pem"
    key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nfake\n")
    config = ApiConfig(  # type: ignore[call-arg]
        _env_file=None,
        GITHUB_APP_ID="1",
        GITHUB_APP_PRIVATE_KEY_PATH=str(key_file),
    )

    assert "fake" in config.require_github_app().private_key

    key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nrotated\n")
    assert "rotated" in config.require_github_app().private_key


def test_token_issuer_and_jwks_come_from_the_better_auth_url() -> None:
    """Better Auth's default `iss` and `aud` are its base URL's origin; any path is dropped."""
    config = ApiConfig(_env_file=None, BETTER_AUTH_URL="https://app.example.test/")  # type: ignore[call-arg]
    assert config.token_issuer == "https://app.example.test"
    assert config.jwks_url == "https://app.example.test/api/auth/jwks"


def test_install_url_needs_the_slug() -> None:
    config = ApiConfig(_env_file=None, GITHUB_APP_SLUG="codesheriff")  # type: ignore[call-arg]
    assert config.install_url == "https://github.com/apps/codesheriff/installations/new"
