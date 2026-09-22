"""Which lines a change touched.

Derived from the two file versions, never from GitHub's `patch`. The rules that matter are the
awkward ones: a deletion has no line of its own to point at, and a whitespace change is not a
change worth analysing.
"""

from __future__ import annotations

from codesheriff_engine.extraction import changed_line_numbers

BEFORE = "def charge(amount):\n    check_limit(amount)\n    return gateway.pay(amount)\n"


def test_an_added_file_reports_every_line_of_code() -> None:
    assert changed_line_numbers(None, 'import os\n\nAPI_KEY = "sk_live"\n') == [1, 3]


def test_an_inserted_line_reports_only_that_line() -> None:
    after = (
        "def charge(amount):\n    check_limit(amount)\n    log(amount)\n"
        "    return gateway.pay(amount)\n"
    )
    assert changed_line_numbers(BEFORE, after) == [3]


def test_a_replaced_line_reports_its_new_position() -> None:
    after = "def charge(amount):\n    check_limit(amount)\n    return gateway.pay(amount * 2)\n"
    assert changed_line_numbers(BEFORE, after) == [3]


def test_an_identical_file_reports_nothing() -> None:
    assert changed_line_numbers(BEFORE, BEFORE) == []


def test_a_whitespace_only_change_reports_nothing() -> None:
    """A blank line carries no code, and a unit built because one appeared is a unit an agent
    pays to analyse for nothing. The unit's `post_src` is still the whole function — this decides
    which functions are worth looking at, not how much of one an agent sees."""
    after = "def charge(amount):\n\n    check_limit(amount)\n\n    return gateway.pay(amount)\n"
    assert changed_line_numbers(BEFORE, after) == []


def test_a_deletion_is_anchored_to_the_line_it_sits_against() -> None:
    """A pure deletion adds no line to post, so it would otherwise report that nothing changed.
    Removing the guard is the whole signal for the access-control CWEs (D-013)."""
    after = "def charge(amount):\n    return gateway.pay(amount)\n"
    assert changed_line_numbers(BEFORE, after) == [2]


def test_a_removed_decorator_is_attributed_to_the_function_it_guarded() -> None:
    before = "class Api:\n    @login_required\n    def export(self):\n        return dump()\n"
    after = "class Api:\n    def export(self):\n        return dump()\n"
    assert changed_line_numbers(before, after) == [2]


def test_a_decorator_replaced_by_a_blank_line_is_still_a_removal() -> None:
    """The form this most often takes in a real diff. Reading it as "only whitespace changed"
    would discard the D-013 signal entirely — which is what the blank-line filter did until a
    `replace` whose new side is all blank was recognised as a deletion too."""
    before = "class Api:\n    @login_required\n    def export(self):\n        return dump()\n"
    after = "class Api:\n\n    def export(self):\n        return dump()\n"
    assert changed_line_numbers(before, after) == [3]


def test_a_deletion_at_the_end_of_a_file_anchors_backwards() -> None:
    """There is no line at or after the gap, so the anchor is the last line of code before it.
    Without the backward search the deletion would fall off the end and vanish."""
    assert changed_line_numbers("x = 1\ny = 2\n", "x = 1\n") == [1]


def test_a_deletion_anchoring_onto_a_blank_line_moves_to_real_code() -> None:
    """The anchor has to survive the blank-line filter, or the deletion is silently lost."""
    before = "def f():\n    audit()\n\n    return 1\n"
    after = "def f():\n\n    return 1\n"
    assert changed_line_numbers(before, after) == [3]


def test_an_emptied_file_reports_nothing_rather_than_raising() -> None:
    assert changed_line_numbers("x = 1\n", "") == []


def test_a_reordering_is_not_reported_as_a_rewrite() -> None:
    """Two functions swap places. difflib matches the common block instead of calling every line
    new, so the change is bounded rather than covering the file.

    It is not empty, and should not be: a swap does move code, and both ends of it are reported.
    The property that matters is that the report is smaller than "all of it" — an extractor that
    marked six lines changed here would build a unit for every function in every reordered file.
    """
    before = "def a():\n    return 1\n\n\ndef b():\n    return 2\n"
    after = "def b():\n    return 2\n\n\ndef a():\n    return 1\n"

    changed = changed_line_numbers(before, after)
    assert 0 < len(changed) < len(after.splitlines())
