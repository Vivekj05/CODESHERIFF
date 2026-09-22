"""Turning a verified repair into a GitHub suggested change, or declining to.

A `suggestion` block is a review comment anchored to a run of lines on the head commit, whose body
replaces those lines when a reviewer clicks "commit suggestion". Two consequences shape this
module.

**It can only be anchored to lines that are in the pull request's diff** (D-095). GitHub rejects a
review comment on a line outside a diff hunk, and this system deliberately never reads GitHub's
`patch` field (D-048), so the hunks are not knowable — only `ChangeUnit.changed_lines`, derived by
diffing the two fetched blobs, is. Those lines are certainly in the diff. Lines outside them may or
may not be, and a suggestion posted on a guess fails the API call and loses the whole comment. So a
repair whose replaced run leaves `changed_lines` is not published, and the summary comment says
that is why. Publishing a fenced code block instead was considered and rejected: to be useful it
would have to carry the file path and the source, and the summary comment carries neither (D-050).

**The body is entirely this system's own words plus the reviewer's own code.** No model prose is
published (D-096), so there is nothing here to screen. What the block says about the repair is the
verification ladder, rung by rung, including the rungs that did not run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from codesheriff_contracts import ChangeUnit
from codesheriff_patch.config import PATCHER_ID, PATCHER_VERSION
from codesheriff_patch.source import LineReplacement
from codesheriff_patch.verify import CheckStatus, Verification

_FENCE_RUN = re.compile(r"`{3,}")

STATUS_WORDING: dict[CheckStatus, str] = {
    CheckStatus.PASSED: "✅ passed",
    CheckStatus.FAILED: "❌ failed",
    CheckStatus.NOT_RUN: "⚪ not run",
}
"""Three statuses, three renderings, always.

A check that could not run renders as its own thing and never as a pass. That is the whole reason
the ladder is published rather than summarised as a badge: "verified" with no list behind it is the
unearned confidence this project exists to argue against."""


@dataclass(frozen=True)
class Anchor:
    """Where a review comment attaches. Lines are 1-based and inclusive, on the head commit."""

    path: str
    commit_sha: str
    start_line: int
    line: int

    @property
    def is_multiline(self) -> bool:
        return self.start_line != self.line


def anchor_for(unit: ChangeUnit, replacement: LineReplacement) -> Anchor | None:
    """The anchor for this repair, or None if it cannot be anchored inside the diff.

    Every replaced line must be one this pull request changed. Not "most of them", and not "the
    first one": GitHub validates the whole span, and a partially-covered span is a failed API call
    at the end of an audit rather than a suggestion.
    """
    start, end = replacement.absolute(unit.start_line)
    changed = set(unit.changed_lines)
    if not changed or not changed.issuperset(range(start, end + 1)):
        return None
    return Anchor(path=unit.file, commit_sha=unit.head_sha, start_line=start, line=end)


def fence_for(lines: tuple[str, ...]) -> str:
    """A backtick fence longer than any run of backticks in the content.

    A Python file may hold ``` inside a docstring — Markdown in a docstring is ordinary — and a
    three-backtick fence around it would close early, publishing half a suggestion as a suggestion
    and the rest as prose the reviewer could commit by accident.
    """
    longest = max((len(m.group()) for line in lines for m in _FENCE_RUN.finditer(line)), default=0)
    return "`" * max(3, longest + 1)


def render(
    cwe: str,
    replacement: LineReplacement,
    verification: Verification,
    dashboard_url: str,
) -> str:
    """The review comment body: what this is, the ladder, the suggestion, and the caveat."""
    fence = fence_for(replacement.lines)
    lines = [
        f"🛡️ **CodeSheriff — suggested repair for `{cwe}`**",
        "",
        "This is a suggestion, not a commit. Nothing is applied unless you apply it.",
        "",
        f"{fence}suggestion",
        *replacement.lines,
        fence,
        "",
        "<details><summary>What was checked before this was posted</summary>",
        "",
        "| Check | Outcome | Detail |",
        "| :--- | :--- | :--- |",
    ]
    for result in verification.results:
        lines.append(
            f"| `{result.name}` | {STATUS_WORDING[result.status]} | {_cell(result.detail)} |"
        )
    lines += [
        "",
        "**CodeSheriff did not run this repository's test suite, and will not.** Pull request "
        "code executes only inside an isolated WebAssembly sandbox with no network and no "
        "filesystem, and a test suite needs all three. A check marked *not run* was not "
        "performed — it is not a check that passed quietly.",
        "",
        "A witness that never detected this weakness cannot certify its removal, so only the "
        "`regression:` rows above are evidence that the repair repaired something. Review the "
        "change on its merits.",
        "</details>",
        "",
        f"[Why this was flagged]({dashboard_url}) · drafted by `{PATCHER_ID}` v{PATCHER_VERSION}",
    ]
    return "\n".join(lines)


def _cell(text: str) -> str:
    """One table cell. Pipes escaped, newlines flattened.

    Every string reaching here is from a closed set of this module's own phrasings plus symbol and
    CWE names, so this is belt to that braces — but a signature rendered into a cell carries
    parameter names chosen by the code author, and `x|--` ends a column.
    """
    return text.replace("|", "\\|").replace("\n", " ")
