"""Fetched blobs to `ChangeUnit`s.

PLAN.md Chapter 8's acceptance criteria live here: units carry a qualified symbol and valid
`post_src` with correct absolute line numbers, and a file GitHub sends no patch for is analysed
rather than silently skipped.
"""

from __future__ import annotations

import pytest

from codesheriff_contracts import ChangeUnit
from codesheriff_engine.extraction import (
    FetchedFile,
    SkipReason,
    extract_units,
    unit_id_for,
)

REPO = "acme/payments-api"
BASE = "b" * 40
HEAD = "h" * 40

BEFORE = """import os

TIMEOUT = 30


class Orders:
    @login_required
    def export(self, request):
        return dump(request.args["scope"])

    def total(self, order):
        return order.amount


def helper(value):
    return value.strip()
"""

AFTER = """import os
import subprocess

TIMEOUT = 30
EXPORT_KEY = "sk_live_51H8xY2"


class Orders:
    def export(self, request):
        return subprocess.run(dump(request.args["scope"]), shell=True)

    def total(self, order):
        return order.amount


def helper(value):
    return value.strip()
"""


def extract(*files: FetchedFile) -> list[ChangeUnit]:
    return extract_units(list(files), repo=REPO, base_sha=BASE, head_sha=HEAD).units


def modified(path: str = "orders/api.py") -> FetchedFile:
    return FetchedFile(path=path, status="modified", post_src=AFTER, pre_src=BEFORE)


def unit_named(units: list[ChangeUnit], qualified: str) -> ChangeUnit:
    return next(u for u in units if u.qualified_symbol == qualified)


# -- the unit of analysis is the changed function (AUDIT.md 4.1) ------------------------------


def test_one_unit_per_changed_function_not_one_per_file() -> None:
    """The superseded parser emitted one unit per file with `symbol=None`, so every finding in a
    file collapsed onto a single `finding_key`."""
    units = extract(modified())
    assert {u.qualified_symbol for u in units} == {"Orders.export", "<module>"}


def test_an_untouched_function_produces_no_unit() -> None:
    """`Orders.total` and `helper` are byte-identical across the change. Analysing them would
    cost an LLM call per unchanged function on every push."""
    assert "helper" not in {u.qualified_symbol for u in extract(modified())}


def test_a_method_qualifies_through_its_class() -> None:
    unit = unit_named(extract(modified()), "Orders.export")
    assert (unit.symbol, unit.enclosing_class) == ("export", "Orders")


def test_units_of_one_function_key_differently_from_another() -> None:
    """The property AUDIT.md 4.1 destroyed: two findings in one file must be two findings."""
    units = extract(modified())
    keys = {u.key_for("CWE-78") for u in units}
    assert len(keys) == len(units)


# -- post_src is real source at real line numbers (AUDIT.md 4.2) -------------------------------


def test_post_src_is_the_function_s_own_source_and_it_parses() -> None:
    """The superseded parser concatenated hunk fragments into source that did not compile."""
    unit = unit_named(extract(modified()), "Orders.export")
    compile(unit.post_src.replace("    ", "", 1), "<unit>", "exec")  # dedent the def line only
    assert unit.post_src.strip().startswith("def export(self, request):")


def test_start_line_locates_post_src_in_the_real_file() -> None:
    unit = unit_named(extract(modified()), "Orders.export")
    file_lines = AFTER.splitlines()
    assert (
        unit.post_src.splitlines()
        == file_lines[unit.start_line - 1 :][: len(unit.post_src.splitlines())]
    )


def test_changed_lines_are_absolute_positions_in_the_file() -> None:
    unit = unit_named(extract(modified()), "Orders.export")
    assert unit.changed_lines
    for line in unit.changed_lines:
        assert unit.start_line <= line <= unit.start_line + len(unit.post_src.splitlines()) - 1
        assert AFTER.splitlines()[line - 1].strip()


def test_pre_src_is_the_previous_version_of_this_function() -> None:
    """Not the diff. `Orders.export` had a `@login_required` that the change removed, and an
    agent can only see that by comparing the two versions of the function."""
    unit = unit_named(extract(modified()), "Orders.export")
    assert unit.pre_src is not None
    assert "@login_required" in unit.pre_src
    assert "@login_required" not in unit.post_src
    assert unit.decorators == []


def test_a_new_function_has_no_pre_src() -> None:
    after = BEFORE + "\n\ndef added(cmd):\n    return os.system(cmd)\n"
    units = extract(FetchedFile("orders/api.py", "modified", after, BEFORE))
    assert unit_named(units, "added").pre_src is None


def test_a_function_that_only_moved_still_has_a_pre_src() -> None:
    """Matched by qualified name rather than by position, so a function pushed down the file is
    not mistaken for a new one."""
    before = "def a(x):\n    return x\n\n\ndef b(x):\n    return eval(x)\n"
    after = "def b(x):\n    return eval(x + '1')\n\n\ndef a(x):\n    return x\n"
    units = extract(FetchedFile("m.py", "modified", after, before))
    assert unit_named(units, "b").pre_src == "def b(x):\n    return eval(x)"


# -- module scope --------------------------------------------------------------------------


def test_a_module_scope_change_becomes_a_module_unit() -> None:
    """CWE-798 sits at module scope more often than not, and this unit is the only way an agent
    ever sees one."""
    unit = unit_named(extract(modified()), "<module>")
    assert unit.symbol is None
    assert 'EXPORT_KEY = "sk_live_51H8xY2"' in unit.post_src


def test_the_module_unit_carries_the_whole_file_untruncated() -> None:
    """Oversized units are for the agent to abstain on, never for extraction to trim."""
    assert unit_named(extract(modified()), "<module>").post_src == AFTER


def test_the_module_unit_claims_only_the_lines_outside_every_function() -> None:
    """Lines inside a function are already carried by that function's unit. Overlapping them
    would present one edit to fusion twice, under two different keys."""
    units = extract(modified())
    module_lines = set(unit_named(units, "<module>").changed_lines)
    export_lines = set(unit_named(units, "Orders.export").changed_lines)
    assert not module_lines & export_lines


def test_a_change_confined_to_functions_produces_no_module_unit() -> None:
    before = "def f(x):\n    return x\n"
    after = "def f(x):\n    return eval(x)\n"
    assert [
        u.qualified_symbol for u in extract(FetchedFile("m.py", "modified", after, before))
    ] == ["f"]


# -- what is skipped, and why it is recorded ------------------------------------------------


@pytest.mark.parametrize(
    ("changed", "reason"),
    [
        (FetchedFile("gone.py", "removed"), SkipReason.FILE_REMOVED),
        (
            FetchedFile("ui/app.ts", "modified", "const a = 1;", "const a = 2;"),
            SkipReason.LANGUAGE_UNSUPPORTED,
        ),
        (
            FetchedFile("big.py", "modified", None, "x = 1\n", SkipReason.CONTENT_UNAVAILABLE),
            SkipReason.CONTENT_UNAVAILABLE,
        ),
        (FetchedFile("moved.py", "renamed", "x = 1\n", "x = 1\n"), SkipReason.NO_CHANGED_LINES),
    ],
)
def test_a_file_that_yields_no_unit_is_recorded_with_its_reason(
    changed: FetchedFile, reason: SkipReason
) -> None:
    """The superseded parser dropped a file with a bare `continue`, so "clean" and "not looked
    at" rendered identically (AUDIT.md 4.4)."""
    result = extract_units([changed], repo=REPO, base_sha=BASE, head_sha=HEAD)
    assert result.units == []
    assert [(s.path, s.reason) for s in result.skipped] == [(changed.path, reason)]


def test_a_file_with_no_patch_is_analysed_rather_than_skipped() -> None:
    """PLAN.md Chapter 8's second acceptance criterion. GitHub omits `patch` on a large diff; the
    old parser skipped exactly those files. Nothing in this package reads `patch` at all, so
    there is no branch that can behave differently for them."""
    units = extract(modified("huge_generated_file.py"))
    assert {u.qualified_symbol for u in units} == {"Orders.export", "<module>"}


# -- identity and stability -----------------------------------------------------------------


def test_a_unit_id_is_unique_per_function_and_stable_across_pushes() -> None:
    assert unit_id_for("a/b.py", "C.m") == unit_id_for("a/b.py", "C.m")
    assert unit_id_for("a/b.py", "C.m") != unit_id_for("a/c.py", "C.m")
    assert unit_id_for("a/b.py", "C.m") != unit_id_for("a/b.py", "D.m")


def test_a_unit_id_fits_the_column_that_stores_it() -> None:
    """`change_units.unit_id` is String(255). A deep path with a long method name has to be
    bounded before the database refuses it and fails the whole audit."""
    assert len(unit_id_for("a/" * 200 + "x.py", "Class" + "Name" * 100 + ".method")) <= 255


def test_a_redefined_symbol_produces_one_unit_not_two() -> None:
    """`@overload` stubs, or a `def` in each branch of a conditional, define the same qualified
    name twice. Both produce the same `finding_key`, so two units would apply one agent's
    likelihood ratio twice to a single finding — and collide on UNIQUE (audit_id, unit_id)."""
    after = (
        "from typing import overload\n\n\n"
        "@overload\ndef run(cmd: str) -> None: ...\n\n\n"
        "def run(cmd):\n    return os.system(cmd)\n"
    )
    units = extract(FetchedFile("m.py", "added", after, None))
    runs = [u for u in units if u.symbol == "run"]
    assert len(runs) == 1
    assert "os.system" in runs[0].post_src, "the implementation wins, not the stub"


def test_a_test_file_is_flagged_but_still_analysed() -> None:
    """Downweighted in Chapter 10, never suppressed: a hard-coded credential in a fixture is
    still a hard-coded credential."""
    units = extract(modified("tests/test_orders.py"))
    assert units
    assert all(u.is_test_file for u in units)


def test_every_unit_carries_the_shas_it_was_built_from() -> None:
    for unit in extract(modified()):
        assert (unit.base_sha, unit.head_sha, unit.repo) == (BASE, HEAD, REPO)


def test_imports_reach_every_unit_of_the_file() -> None:
    """A function's units need the module's imports to know what `subprocess.run` resolves to."""
    for unit in extract(modified()):
        assert unit.imports == ["import os", "import subprocess"]
