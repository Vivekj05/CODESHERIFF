"""Tests for REST API and Dashboard endpoints."""

import sys
from pathlib import Path

_root = Path(__file__).parent.parent.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_dashboard_endpoint() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "CODESHERIFF" in response.text


def test_health_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "service": "codesheriff-engine"}


def test_audit_api_endpoint() -> None:
    payload = {
        "unit_id": "test-api-01",
        "repo": "acme/webapp",
        "language": "python",
        "file": "app/api/users.py",
        "post_src": "def get_user(uid):\n    q = f\"SELECT * FROM users WHERE id = {uid}\"\n    return cursor.execute(q).fetchone()\n",
        "pre_src": "def get_user(uid):\n    return f'User {uid}'\n",
        "changed_lines": [1, 2],
        "base_sha": "aaaaaaa",
        "head_sha": "bbbbbbb",
    }
    response = client.post("/api/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "joint_posterior_prob" in data
    assert "verdict" in data
    assert "patched_code" in data
    assert "evidence" in data


def test_create_pr_api_endpoint() -> None:
    payload = {
        "repo": "acme/webapp",
        "branch_name": "fix/codesheriff-patch-001",
        "title": "fix(security): resolve SQL injection vulnerability",
        "body": "Verified automated patch by CodeSheriff.",
        "file_path": "app/api/users.py",
        "content": "def get_user(uid):\n    q = \"SELECT * FROM users WHERE id = %s\"\n    return cursor.execute(q, (uid,)).fetchone()\n",
    }
    response = client.post("/api/create-pr", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "pr_url" in data
    assert "branch" in data
    assert data["branch"] == "fix/codesheriff-patch-001"
