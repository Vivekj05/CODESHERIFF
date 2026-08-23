"""GitHub PR Diff & Payload parser to ChangeUnit contracts."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from codesheriff_engine.contracts import ChangeUnit

EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".rs": "rust",
}


def detect_language(filename: str) -> str:
    """Infer programming language from file extension."""
    for ext, lang in EXTENSION_TO_LANGUAGE.items():
        if filename.endswith(ext):
            return lang
    return "unknown"


def is_test_path(filename: str) -> bool:
    """Check if file is located in a test directory or has a test prefix/suffix."""
    lower = filename.lower()
    return any(
        pattern in lower
        for pattern in ["test_", "_test.", "/tests/", "/test/", "/spec/", "_spec.", ".test.", ".spec."]
    )


def parse_patch_lines(patch: str) -> tuple[str, str, List[int], int]:
    """Parse a unified git diff patch to reconstruct pre_src, post_src, changed lines, and start line.
    
    Returns:
        (pre_src, post_src, changed_lines, start_line)
    """
    pre_lines: List[str] = []
    post_lines: List[str] = []
    changed_lines: List[int] = []

    current_post_line = 1
    start_line = 1

    hunk_header_re = re.compile(r"^@@\s+-\d+(?:,\d+)?\s+\+(\d+)(?:,\d+)?\s+@@")

    for line in patch.splitlines():
        hunk_match = hunk_header_re.match(line)
        if hunk_match:
            current_post_line = int(hunk_match.group(1))
            if start_line == 1:
                start_line = current_post_line
            continue

        if line.startswith("+") and not line.startswith("+++"):
            content = line[1:]
            post_lines.append(content)
            changed_lines.append(current_post_line)
            current_post_line += 1
        elif line.startswith("-") and not line.startswith("---"):
            content = line[1:]
            pre_lines.append(content)
        else:
            # Context line (starts with space or empty)
            content = line[1:] if line.startswith(" ") else line
            pre_lines.append(content)
            post_lines.append(content)
            current_post_line += 1

    pre_src = "\n".join(pre_lines) + ("\n" if pre_lines else "")
    post_src = "\n".join(post_lines) + ("\n" if post_lines else "")

    return pre_src, post_src, changed_lines, start_line


def parse_pr_files_to_change_units(
    repo_full_name: str,
    pr_number: int,
    pr_files: List[Dict[str, Any]],
    base_sha: str = "base_sha",
    head_sha: str = "head_sha",
) -> List[ChangeUnit]:
    """Convert GitHub API PR files list into a list of ChangeUnits for security auditing."""
    units: List[ChangeUnit] = []

    for idx, file_info in enumerate(pr_files, start=1):
        filename = file_info.get("filename", "")
        status = file_info.get("status", "")
        patch = file_info.get("patch", "")

        # Skip deleted files or non-code files
        if status == "removed" or not patch:
            continue

        language = detect_language(filename)
        if language == "unknown":
            continue

        pre_src, post_src, changed_lines, start_line = parse_patch_lines(patch)

        unit_id = f"pr-{pr_number}-file-{idx}"
        unit = ChangeUnit(
            contract_version="1.0.0",
            unit_id=unit_id,
            repo=repo_full_name,
            language=language,
            file=filename,
            symbol=None,
            pre_src=pre_src,
            post_src=post_src,
            changed_lines=changed_lines,
            start_line=start_line,
            base_sha=base_sha,
            head_sha=head_sha,
            is_test_file=is_test_path(filename),
        )
        units.append(unit)

    return units
