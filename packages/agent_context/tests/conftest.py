"""Global pytest configuration and fixtures for Context Agent."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict
import pytest
from context_agent.contracts import ChangeUnit


@pytest.fixture
def sample_unit() -> ChangeUnit:
    """Provide sample_unit payload."""
    p = Path(__file__).parent / "fixtures" / "sample_unit.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    return ChangeUnit.model_validate(data)


@pytest.fixture
def sample_unit_safe() -> ChangeUnit:
    """Provide sample_unit_safe payload."""
    p = Path(__file__).parent / "fixtures" / "sample_unit_safe.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    return ChangeUnit.model_validate(data)


@pytest.fixture
def sample_past_pr() -> Dict[str, Any]:
    """Provide sample_past_pr metadata dict."""
    p = Path(__file__).parent / "fixtures" / "sample_past_pr.json"
    return json.loads(p.read_text(encoding="utf-8"))


@pytest.fixture
def sample_bypassing_unit() -> ChangeUnit:
    """Provide sample_bypassing_unit payload."""
    p = Path(__file__).parent / "fixtures" / "sample_bypassing_unit.json"
    data = json.loads(p.read_text(encoding="utf-8"))
    return ChangeUnit.model_validate(data)
