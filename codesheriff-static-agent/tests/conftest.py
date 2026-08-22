"""Pytest conftest setup and shared fixtures."""

import json
from pathlib import Path
import pytest
from static_agent.contracts import ChangeUnit


@pytest.fixture
def sample_unit() -> ChangeUnit:
    p = Path(__file__).parent / "fixtures" / "sample_unit.json"
    return ChangeUnit(**json.loads(p.read_text(encoding="utf-8")))


@pytest.fixture
def sample_unit_safe() -> ChangeUnit:
    p = Path(__file__).parent / "fixtures" / "sample_unit_safe.json"
    return ChangeUnit(**json.loads(p.read_text(encoding="utf-8")))
