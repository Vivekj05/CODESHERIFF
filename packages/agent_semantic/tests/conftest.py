"""Fixtures for the semantic agent tests.

**No test reaches the network**, and that is a Chapter 11 acceptance criterion ("zero live API
calls in the suite"), not a convention. An autouse fixture blocks every non-loopback socket
connection unless `CODESHERIFF_ALLOW_LIVE_CALLS` is set — a guard at the socket layer, so a
forgotten mock cannot leak a real request.

The guard matters more here than anywhere else in the repository. This is the only package that
holds an API key and the only one whose calls cost money against a free-tier quota, and a suite
that quietly spends quota is one nobody can run in CI. The `--live-api` option and the `live_api`
marker are kept for tests deliberately written to call out, and they are skipped by default.
"""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from codesheriff_contracts import ChangeUnit

LOOPBACK = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live-api",
        action="store_true",
        default=False,
        help="Run tests marked `live_api`, which call a real LLM provider and spend quota.",
    )


@pytest.fixture(autouse=True)
def block_live_calls(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any connection that is not loopback.

    A `live_api` test that was explicitly requested is let through; everything else is blocked at
    the socket, so an un-stubbed client raises with a message naming the problem instead of
    silently working on the machine of whoever has a key configured.
    """
    wants_live = request.node.get_closest_marker("live_api") and request.config.getoption(
        "--live-api"
    )
    if wants_live or os.environ.get("CODESHERIFF_ALLOW_LIVE_CALLS"):
        return

    real_connect = socket.socket.connect

    def guarded(self: socket.socket, address: object) -> object:
        host = address[0] if isinstance(address, tuple) else str(address)
        if str(host) in LOOPBACK:
            return real_connect(self, address)  # type: ignore[arg-type]
        raise RuntimeError(
            f"A test tried to open a live connection to {host!r}. The suite must make zero live "
            f"API calls (PLAN.md Chapter 11). Inject an LLMClient, or replay a cassette."
        )

    monkeypatch.setattr(socket.socket, "connect", guarded)


@pytest.fixture(autouse=True)
def skip_unrequested_live_tests(request: pytest.FixtureRequest) -> None:
    """A `live_api` test does nothing unless `--live-api` was passed."""
    if request.node.get_closest_marker("live_api") and not request.config.getoption("--live-api"):
        pytest.skip("live API test; pass --live-api to run it")


@pytest.fixture
def sample_unit() -> ChangeUnit:
    """The vulnerable sample unit."""
    path = Path(__file__).parent / "fixtures" / "sample_unit.json"
    return ChangeUnit.model_validate(json.loads(path.read_text(encoding="utf-8")))


@pytest.fixture
def sample_unit_safe() -> ChangeUnit:
    """Its safe twin."""
    path = Path(__file__).parent / "fixtures" / "sample_unit_safe.json"
    return ChangeUnit.model_validate(json.loads(path.read_text(encoding="utf-8")))
