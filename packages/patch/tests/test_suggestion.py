"""Anchoring a repair inside the diff, and rendering it without a word of model prose."""

from __future__ import annotations

from codesheriff_contracts import ChangeUnit
from codesheriff_patch.source import line_replacement
from codesheriff_patch.suggestion import anchor_for, fence_for, render
from codesheriff_patch.verify import CheckResult, CheckStatus, Verification


class TestAnchoring:
    def test_a_repair_inside_the_changed_lines_anchors(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        replacement = line_replacement(unit.post_src, repaired)
        assert replacement is not None
        anchor = anchor_for(unit, replacement)
        assert anchor is not None
        assert (anchor.start_line, anchor.line) == (11, 12)
        assert anchor.path == "app/db.py"
        assert anchor.commit_sha == unit.head_sha
        assert anchor.is_multiline

    def test_a_repair_reaching_one_line_outside_the_diff_does_not(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        # GitHub validates the whole span. A partially-covered one is a failed API call at the end
        # of an audit, not a suggestion — so it is declined here instead.
        narrowed = unit.model_copy(update={"changed_lines": [10, 11]})
        replacement = line_replacement(narrowed.post_src, repaired)
        assert replacement is not None
        assert anchor_for(narrowed, replacement) is None

    def test_a_unit_with_no_changed_lines_cannot_be_anchored(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        empty = unit.model_copy(update={"changed_lines": []})
        replacement = line_replacement(empty.post_src, repaired)
        assert replacement is not None
        assert anchor_for(empty, replacement) is None

    def test_a_single_line_repair_anchors_to_one_line(self, unit: ChangeUnit) -> None:
        one_line = unit.post_src.replace(
            '        query = "SELECT * FROM users WHERE id = " + user_id',
            '        query = "SELECT * FROM users WHERE id = ?"',
        )
        replacement = line_replacement(unit.post_src, one_line)
        assert replacement is not None
        anchor = anchor_for(unit, replacement)
        assert anchor is not None
        assert not anchor.is_multiline
        assert anchor.start_line == anchor.line == 11


class TestFencing:
    def test_ordinary_code_gets_three_backticks(self) -> None:
        assert fence_for(("    return 1",)) == "```"

    def test_a_docstring_holding_a_fence_forces_a_longer_one(self) -> None:
        # Markdown in a docstring is ordinary. A three-backtick fence would close early,
        # publishing half a suggestion as a suggestion and the rest as prose.
        assert fence_for(('    """```python"""',)) == "````"

    def test_it_outgrows_the_longest_run_present(self) -> None:
        assert fence_for(("`````",)) == "``````"


class TestRendering:
    def _verification(self) -> Verification:
        return Verification(
            results=(
                CheckResult("parses", CheckStatus.PASSED, "parses as valid Python"),
                CheckResult("regression:structural", CheckStatus.PASSED, "no longer detected"),
                CheckResult("regression:runtime", CheckStatus.NOT_RUN, "no interpreter"),
            )
        )

    def test_the_body_carries_a_suggestion_block_with_the_replacement(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        replacement = line_replacement(unit.post_src, repaired)
        assert replacement is not None
        body = render("CWE-89", replacement, self._verification(), "https://dash/audits/1")
        assert "```suggestion" in body
        assert '        query = "SELECT * FROM users WHERE id = ?"' in body

    def test_a_check_that_did_not_run_never_renders_as_a_pass(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        replacement = line_replacement(unit.post_src, repaired)
        assert replacement is not None
        body = render("CWE-89", replacement, self._verification(), "https://dash/audits/1")
        row = next(line for line in body.splitlines() if "regression:runtime" in line)
        assert "not run" in row
        assert "passed" not in row

    def test_it_says_the_repository_s_tests_were_not_run(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        # §7 open question 3, answered on the page a reviewer actually reads (D-094).
        replacement = line_replacement(unit.post_src, repaired)
        assert replacement is not None
        body = render("CWE-89", replacement, self._verification(), "https://dash/audits/1")
        assert "did not run this repository's test suite" in body

    def test_it_says_this_is_a_suggestion_and_not_a_commit(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        replacement = line_replacement(unit.post_src, repaired)
        assert replacement is not None
        body = render("CWE-89", replacement, self._verification(), "https://dash/audits/1")
        assert "not a commit" in body

    def test_a_pipe_in_a_check_detail_cannot_break_the_table(
        self, unit: ChangeUnit, repaired: str
    ) -> None:
        replacement = line_replacement(unit.post_src, repaired)
        assert replacement is not None
        verification = Verification(
            results=(CheckResult("parses", CheckStatus.FAILED, "def f(a|b, c)"),)
        )
        body = render("CWE-89", replacement, verification, "https://dash/audits/1")
        assert r"def f(a\|b, c)" in body
