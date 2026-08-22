"""Global pytest configuration and fixtures."""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from semantic_agent.contracts import ChangeUnit


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live-api",
        action="store_true",
        default=False,
        help="Run tests that make live API calls to LLM providers.",
    )


@pytest.fixture(autouse=True)
def guard_against_accidental_live_api(request: pytest.FixtureRequest) -> None:
    """Guard fixture preventing unintended external network/API requests."""
    if request.node.get_closest_marker("live_api") and not request.config.getoption("--live-api"):
        pytest.skip("Skipping live API test. Pass --live-api to execute.")


@pytest.fixture
def sample_unit() -> ChangeUnit:
    """Fixture providing the vulnerable sample_unit payload."""
    p = Path(__file__).parent / "fixtures" / "sample_unit.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    return ChangeUnit.model_validate(data)


@pytest.fixture
def sample_unit_safe() -> ChangeUnit:
    """Fixture providing the safe twin sample_unit_safe payload."""
    p = Path(__file__).parent / "fixtures" / "sample_unit_safe.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    return ChangeUnit.model_validate(data)
