"""Unit tests for GitHub PR payload and diff parser."""

from codesheriff_engine.github.parser import (
    detect_language,
    is_test_path,
    parse_patch_lines,
    parse_pr_files_to_change_units,
)


def test_detect_language() -> None:
    assert detect_language("app/main.py") == "python"
    assert detect_language("server/index.js") == "javascript"
    assert detect_language("src/component.tsx") == "typescript"
    assert detect_language("cmd/main.go") == "go"
    assert detect_language("README.md") == "unknown"


def test_is_test_path() -> None:
    assert is_test_path("tests/test_api.py") is True
    assert is_test_path("src/api_test.go") is True
    assert is_test_path("spec/user_spec.rb") is True
    assert is_test_path("src/auth/service.py") is False


def test_parse_patch_lines() -> None:
    sample_patch = (
        "@@ -10,3 +10,4 @@\n"
        " def handle():\n"
        "-    query = 'SELECT 1'\n"
        "+    name = request.args.get('name')\n"
        "+    query = f'SELECT * FROM users WHERE name = {name}'\n"
        "     cursor.execute(query)\n"
    )

    pre_src, post_src, changed_lines, start_line = parse_patch_lines(sample_patch)

    assert start_line == 10
    assert 11 in changed_lines
    assert 12 in changed_lines
    assert "request.args.get" in post_src
    assert "SELECT 1" in pre_src
    assert "SELECT 1" not in post_src


def test_parse_pr_files_to_change_units() -> None:
    pr_files = [
        {
            "filename": "app/users.py",
            "status": "modified",
            "patch": "@@ -1,2 +1,3 @@\n def get():\n+    return 1\n",
        },
        {
            "filename": "docs/README.md",
            "status": "modified",
            "patch": "@@ -1 +1 @@\n-# Docs\n+# New Docs\n",
        },
        {
            "filename": "deleted_file.py",
            "status": "removed",
        },
    ]

    units = parse_pr_files_to_change_units(
        repo_full_name="acme/app",
        pr_number=10,
        pr_files=pr_files,
    )

    # Only app/users.py should be converted (README is non-code, deleted_file is removed)
    assert len(units) == 1
    u = units[0]
    assert u.repo == "acme/app"
    assert u.file == "app/users.py"
    assert u.language == "python"
    assert u.unit_id == "pr-10-file-1"
