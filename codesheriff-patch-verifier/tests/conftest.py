"""Pytest configuration for patch-verifier tests."""

import pytest
from patch_verifier.contracts import ChangeUnit, Evidence


@pytest.fixture
def sample_change_unit() -> ChangeUnit:
    return ChangeUnit(
        unit_id="demo-patch-001",
        repo="acme/webapp",
        language="python",
        file="app/api/users.py",
        symbol="get_user",
        pre_src="def get_user(uid):\n    return f'User {uid}'\n",
        post_src="def get_user():\n    q = f\"SELECT * FROM users WHERE id = {uid}\"\n    return cursor.execute(q).fetchone()\n",
        changed_lines=[1, 2, 3],
        base_sha="aaaaaaa",
        head_sha="bbbbbbb",
    )


@pytest.fixture
def sample_evidence(sample_change_unit: ChangeUnit) -> Evidence:
    return Evidence(
        agent_id="structural.taint",
        agent_version="0.1.0",
        unit_id=sample_change_unit.unit_id,
        finding_key="find_001",
        cwe="CWE-89",
        raw_score=0.95,
        confidence=0.9,
        explanation="Taint path detected: user input flowed to cursor.execute",
    )
