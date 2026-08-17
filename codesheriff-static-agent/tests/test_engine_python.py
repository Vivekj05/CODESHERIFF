"""Tests for Python taint engine analysis."""

from static_agent.config import StaticConfig
from static_agent.contracts import ChangeUnit
from static_agent.taint.engine import analyze_taint


def test_python_sqli_detection() -> None:
    unit = ChangeUnit(
        contract_version="1.0.0",
        unit_id="test-py-01",
        repo="acme/app",
        language="python",
        file="app/users.py",
        symbol="get_user",
        pre_src="def get_user(uid): pass",
        post_src="def get_user():\n    uid = request.args.get('id')\n    q = f'SELECT * FROM users WHERE id = {uid}'\n    cursor.execute(q)\n",
        changed_lines=[1, 2, 3, 4],
        start_line=1,
        base_sha="aaa",
        head_sha="bbb",
    )
    results = analyze_taint(unit, StaticConfig())
    assert len(results) == 1
    assert results[0].cwe == "CWE-89"


def test_python_os_command_injection() -> None:
    unit = ChangeUnit(
        contract_version="1.0.0",
        unit_id="test-py-02",
        repo="acme/app",
        language="python",
        file="app/tasks.py",
        symbol="run_cmd",
        pre_src="def run_cmd(): pass",
        post_src="import os\ndef run_cmd():\n    cmd = request.args['cmd']\n    os.system(cmd)\n",
        changed_lines=[1, 2, 3],
        start_line=1,
        base_sha="aaa",
        head_sha="bbb",
    )
    results = analyze_taint(unit, StaticConfig())
    assert len(results) == 1
    assert results[0].cwe == "CWE-78"
