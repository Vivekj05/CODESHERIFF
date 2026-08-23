"""Pytest fixtures and configuration for codesheriff-engine tests."""

import pytest
from typing import Any, Dict, List
from codesheriff_engine.contracts import Artifact, ChangeUnit, Evidence, finding_key


@pytest.fixture
def sample_vulnerable_unit() -> ChangeUnit:
    """Sample vulnerable ChangeUnit (SQL injection in users.py)."""
    return ChangeUnit(
        contract_version="1.0.0",
        unit_id="demo-sqli-001",
        repo="acme/webapp",
        language="python",
        file="app/api/users.py",
        symbol="get_user",
        pre_src="def get_user(user_id):\n    return db.query(User).get(user_id)\n",
        post_src=(
            "def get_user():\n"
            "    uid = request.args.get('id')\n"
            "    q = f\"SELECT * FROM users WHERE id = {uid}\"\n"
            "    return cursor.execute(q).fetchone()\n"
        ),
        changed_lines=[1, 2, 3, 4],
        start_line=42,
        neighbours=[],
        imports=["flask.request", "app.db.cursor"],
        base_sha="aaaaaaa",
        head_sha="bbbbbbb",
        is_test_file=False,
    )


@pytest.fixture
def sample_safe_unit() -> ChangeUnit:
    """Sample safe ChangeUnit (parameterized query)."""
    return ChangeUnit(
        contract_version="1.0.0",
        unit_id="demo-safe-001",
        repo="acme/webapp",
        language="python",
        file="app/api/users.py",
        symbol="get_user",
        pre_src="def get_user(user_id):\n    return db.query(User).get(user_id)\n",
        post_src=(
            "def get_user():\n"
            "    uid = request.args.get('id')\n"
            "    return cursor.execute('SELECT * FROM users WHERE id = %s', (uid,)).fetchone()\n"
        ),
        changed_lines=[1, 2, 3],
        start_line=42,
        neighbours=[],
        imports=["flask.request", "app.db.cursor"],
        base_sha="aaaaaaa",
        head_sha="bbbbbbb",
        is_test_file=False,
    )


@pytest.fixture
def target_sqli_finding_key() -> str:
    return finding_key("app/api/users.py", "get_user", "CWE-89", 'cursor.execute(q).fetchone()')


@pytest.fixture
def sample_evidence_list(target_sqli_finding_key: str) -> List[Evidence]:
    """Sample evidence items from Static, Semantic, and Context agents on the same finding."""
    return [
        Evidence(
            agent_id="structural.taint",
            agent_version="0.1.0",
            unit_id="demo-sqli-001",
            finding_key=target_sqli_finding_key,
            cwe="CWE-89",
            raw_score=0.95,
            confidence=0.90,
            explanation="Taint path from request.args.get reaching cursor.execute sink.",
        ),
        Evidence(
            agent_id="semantic.hosted",
            agent_version="0.1.0",
            unit_id="demo-sqli-001",
            finding_key=target_sqli_finding_key,
            cwe="CWE-89",
            raw_score=0.90,
            confidence=0.95,
            explanation="Direct f-string SQL query formatting without parameterization.",
        ),
        Evidence(
            agent_id="context.rag",
            agent_version="0.1.0",
            unit_id="demo-sqli-001",
            finding_key=target_sqli_finding_key,
            cwe="CWE-89",
            raw_score=0.85,
            confidence=0.80,
            explanation="Bypasses ORM security standard introduced in past PR #42.",
        ),
    ]
