"""Pytest configuration for runtime-agent tests."""

import pytest
from runtime_agent.contracts import ChangeUnit

@pytest.fixture
def sample_change_unit() -> ChangeUnit:
    return ChangeUnit(
        unit_id="demo-runtime-001",
        repo="acme/webapp",
        language="python",
        file="app/api/users.py",
        symbol="get_user",
        pre_src="def get_user(uid):\n    return f'User {uid}'\n",
        post_src="def get_user(uid):\n    return f'User {uid}'\n",
        changed_lines=[1, 2],
        base_sha="aaaaaaa",
        head_sha="bbbbbbb",
    )
