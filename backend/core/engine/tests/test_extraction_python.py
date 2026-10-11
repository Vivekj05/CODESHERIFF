"""The tree-sitter walk over one whole Python file.

These tests are about the *shape* a file is read into: which definitions become symbols, where
each one starts and ends, and what a symbol carries with it. Nothing here diffs anything.
"""

from __future__ import annotations

from codesheriff_engine.extraction import parse_python_file

MODULE = '''"""A module."""

import os
from pathlib import Path

DEFAULT_ROOT = "/srv"


class Store:
    """A class."""

    @property
    def root(self) -> str:
        return DEFAULT_ROOT

    @audited(actor="system")
    @requires_role("admin")
    async def purge(self, key):
        def sanitise(value):
            return value.strip()

        return os.remove(sanitise(key))


def helper(path):
    return Path(path)
'''


def parsed() -> object:
    return parse_python_file(MODULE)


def test_every_outermost_function_becomes_a_symbol() -> None:
    names = [(s.enclosing_class, s.name) for s in parse_python_file(MODULE).symbols]
    assert names == [("Store", "root"), ("Store", "purge"), (None, "helper")]


def test_a_nested_function_is_part_of_its_parent_and_not_a_symbol() -> None:
    """`sanitise` is a closure. A unit containing only it would be a fragment whose free
    variables are bound outside — the AUDIT.md 4.2 failure reached from the other direction."""
    assert "sanitise" not in {s.name for s in parse_python_file(MODULE).symbols}

    purge = next(s for s in parse_python_file(MODULE).symbols if s.name == "purge")
    assert "def sanitise(value):" in purge.source


def test_line_numbers_are_the_file_s_own() -> None:
    lines = MODULE.splitlines()
    for symbol in parse_python_file(MODULE).symbols:
        first = lines[symbol.start_line - 1]
        assert first.strip().startswith(("def ", "async def ", "@"))
        assert symbol.source.splitlines() == lines[symbol.start_line - 1 : symbol.end_line]


def test_a_decorated_symbol_starts_at_its_first_decorator() -> None:
    """The span has to include the decorators, or a pull request that deletes one changes a line
    that belongs to no unit and the D-013 signal is lost."""
    purge = next(s for s in parse_python_file(MODULE).symbols if s.name == "purge")
    assert MODULE.splitlines()[purge.start_line - 1].strip() == '@audited(actor="system")'


def test_decorators_keep_their_arguments() -> None:
    """`@requires_role("admin")` and `@requires_role("viewer")` are different guards. Reducing
    both to `requires_role` makes a pull request that weakens one look like a no-op."""
    purge = next(s for s in parse_python_file(MODULE).symbols if s.name == "purge")
    assert purge.decorators == ('audited(actor="system")', 'requires_role("admin")')


def test_async_functions_are_symbols() -> None:
    purge = next(s for s in parse_python_file(MODULE).symbols if s.name == "purge")
    assert purge.source.lstrip().startswith("@audited")
    assert "async def purge" in purge.source


def test_module_scope_imports_are_collected() -> None:
    assert parse_python_file(MODULE).imports == ("import os", "from pathlib import Path")


def test_an_import_inside_a_function_is_not_a_module_import() -> None:
    """It is already in that function's source, which the agent receives in full."""
    parsed = parse_python_file("def f():\n    import pickle\n    return pickle\n")
    assert parsed.imports == ()


def test_imports_guarded_by_a_conditional_are_still_module_imports() -> None:
    """A walk that only looked at direct module children would miss these silently."""
    source = "try:\n    import ujson as json\nexcept ImportError:\n    import json\n"
    assert parse_python_file(source).imports == ("import ujson as json", "import json")


def test_a_function_defined_inside_a_conditional_is_found() -> None:
    source = "if FEATURE:\n    def handler(req):\n        return req\n"
    assert [s.name for s in parse_python_file(source).symbols] == ["handler"]


def test_a_nested_class_qualifies_by_its_innermost_class() -> None:
    """`ChangeUnit` carries one level of qualification, and the file path already distinguishes
    this `Inner` from any other."""
    source = "class Outer:\n    class Inner:\n        def m(self):\n            return 1\n"
    symbol = parse_python_file(source).symbols[0]
    assert (symbol.enclosing_class, symbol.name) == ("Inner", "m")


def test_a_decorated_class_does_not_hide_its_methods() -> None:
    source = "@dataclass\nclass C:\n    def m(self):\n        return 1\n"
    symbol = parse_python_file(source).symbols[0]
    assert (symbol.enclosing_class, symbol.name) == ("C", "m")


def test_a_syntax_error_does_not_lose_the_rest_of_the_file() -> None:
    """A pull request head commit frequently does not parse. tree-sitter recovers; Python's own
    `ast` would raise and the whole file would go unanalysed."""
    source = "def broken(:\n    return 1\n\n\ndef fine():\n    eval(untrusted)\n"
    names = [s.name for s in parse_python_file(source).symbols]
    assert "fine" in names


def test_symbol_for_finds_the_owning_function() -> None:
    parsed = parse_python_file(MODULE)
    purge = next(s for s in parsed.symbols if s.name == "purge")
    assert parsed.symbol_for(purge.start_line) is purge
    assert parsed.symbol_for(purge.end_line) is purge


def test_symbol_for_returns_none_at_module_scope() -> None:
    parsed = parse_python_file(MODULE)
    constant = MODULE.splitlines().index('DEFAULT_ROOT = "/srv"') + 1
    assert parsed.symbol_for(constant) is None


def test_indentation_survives_the_slice() -> None:
    """Sliced by line, not by byte offset. A byte slice starts at the `def` keyword and silently
    dedents the first line of every method."""
    symbol = parse_python_file("class C:\n    def m(self):\n        return 1\n").symbols[0]
    assert symbol.source.startswith("    def m")
