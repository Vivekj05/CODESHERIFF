"""Parsing a function as the file holds it, and narrowing a repair to the lines it touches."""

from __future__ import annotations

from collections.abc import Callable

from codesheriff_patch.source import (
    Signature,
    free_names,
    line_replacement,
    names_available_from,
    parse,
    signature_of,
)


class TestParsing:
    def test_a_method_indented_as_the_file_holds_it_still_parses(self, vulnerable: str) -> None:
        # `post_src` carries the file's leading whitespace. Parsing it without dedenting is an
        # IndentationError, and a syntax gate that fell over on every method would reject every
        # correct patch to one.
        assert vulnerable.startswith("    def ")
        assert parse(vulnerable) is not None

    def test_broken_source_is_refused_rather_than_tolerated(self) -> None:
        # tree-sitter would build a tree for this; `ast` will not, and refusing is the point.
        assert parse("def f(:\n    pass") is None

    def test_a_null_byte_is_refused_without_raising(self) -> None:
        assert parse("def f():\n    x = '\x00'\n") is None


class TestSignature:
    def test_every_parameter_kind_is_part_of_the_signature(self) -> None:
        source = "def f(a, /, b, *args, c, **kwargs):\n    pass"
        assert signature_of(source) == Signature(
            name="f", parameters=("a", "b", "args", "c", "kwargs"), is_async=False
        )

    def test_async_is_part_of_it(self) -> None:
        assert signature_of("async def f():\n    pass") != signature_of("def f():\n    pass")

    def test_source_defining_two_functions_has_no_single_signature(self) -> None:
        assert signature_of("def f():\n    pass\ndef g():\n    pass") is None

    def test_a_repair_that_changes_only_the_body_keeps_the_signature(
        self, vulnerable: str, repaired: str
    ) -> None:
        assert signature_of(vulnerable) == signature_of(repaired)


class TestFreeNames:
    def test_a_module_the_function_never_imports_reads_free(
        self, indent_like_a_file: Callable[..., str]
    ) -> None:
        source = indent_like_a_file(
            """
            def run(self, name):
                return shlex.quote(name)
            """,
            indent=4,
        )
        assert "shlex" in free_names(source)

    def test_a_locally_imported_module_does_not(
        self, indent_like_a_file: Callable[..., str]
    ) -> None:
        source = indent_like_a_file(
            """
            def run(self, name):
                import shlex

                return shlex.quote(name)
            """,
            indent=4,
        )
        assert "shlex" not in free_names(source)

    def test_builtins_are_not_free(self) -> None:
        assert free_names("def f(x):\n    return len(sorted(x))") == frozenset()

    def test_parameters_and_locals_are_bound(self) -> None:
        assert free_names("def f(x):\n    y = x\n    return y") == frozenset()

    def test_source_that_does_not_parse_reports_nothing_rather_than_guessing(self) -> None:
        assert free_names("def f(:") == frozenset()


class TestImportedNames:
    def test_a_dotted_import_binds_only_its_first_component(self) -> None:
        # `import os.path` binds `os`. Binding `os.path` would let a draft reference a submodule
        # nothing imported.
        assert names_available_from(["import os.path"]) == frozenset({"os"})

    def test_an_alias_binds_the_alias(self) -> None:
        assert names_available_from(["import numpy as np"]) == frozenset({"np"})

    def test_from_import_binds_the_imported_name(self) -> None:
        assert names_available_from(["from shlex import quote"]) == frozenset({"quote"})

    def test_an_unparseable_statement_is_skipped_not_fatal(self) -> None:
        assert names_available_from(["import ;;;", "import os"]) == frozenset({"os"})


class TestLineReplacement:
    def test_it_narrows_to_the_lines_that_actually_changed(
        self, vulnerable: str, repaired: str
    ) -> None:
        replacement = line_replacement(vulnerable, repaired)
        assert replacement is not None
        # Line 0 is `def lookup(...)` and is untouched, so the run starts at 1.
        assert (replacement.start_index, replacement.end_index) == (1, 2)
        assert replacement.replaced_line_count == 2

    def test_the_replacement_carries_the_file_s_own_indentation(
        self, vulnerable: str, repaired: str
    ) -> None:
        replacement = line_replacement(vulnerable, repaired)
        assert replacement is not None
        assert all(line.startswith("        ") for line in replacement.lines)

    def test_absolute_lines_are_the_file_s_line_numbers(
        self, vulnerable: str, repaired: str
    ) -> None:
        replacement = line_replacement(vulnerable, repaired)
        assert replacement is not None
        assert replacement.absolute(unit_start_line=10) == (11, 12)

    def test_an_identical_draft_replaces_nothing(self, vulnerable: str) -> None:
        assert line_replacement(vulnerable, vulnerable) is None

    def test_a_pure_insertion_widens_to_a_real_line(self) -> None:
        # GitHub cannot anchor a suggestion to zero lines, so the run is widened backwards by one
        # and that line is carried through unchanged. Applying the result reproduces the draft
        # exactly, which is the only property that matters; which side it widens to is a
        # deterministic choice, not a meaningful one.
        before = "def f(x):\n    return x"
        after = "def f(x):\n    x = int(x)\n    return x"
        replacement = line_replacement(before, after)
        assert replacement is not None
        assert replacement.replaced_line_count == 1
        assert replacement.start_index == 0
        assert replacement.lines == ("def f(x):", "    x = int(x)")

    def test_applying_a_replacement_reproduces_the_draft(
        self, vulnerable: str, repaired: str
    ) -> None:
        # The property behind every anchoring decision: splice the replacement back over the run
        # it names and you get the patch the model wrote, byte for byte.
        for before, after in [
            (vulnerable, repaired),
            ("def f(x):\n    return x", "def f(x):\n    x = int(x)\n    return x"),
            ("def f(x):\n    eval(x)\n    return x", "def f(x):\n    return x"),
            ("def f(x):\n    return x", "@guard\ndef f(x):\n    return x"),
        ]:
            replacement = line_replacement(before, after)
            assert replacement is not None
            lines = before.splitlines()
            spliced = [
                *lines[: replacement.start_index],
                *replacement.lines,
                *lines[replacement.end_index + 1 :],
            ]
            assert "\n".join(spliced) == after

    def test_an_insertion_at_the_very_top_widens_forwards(self) -> None:
        before = "def f(x):\n    return x"
        after = "@guard\ndef f(x):\n    return x"
        replacement = line_replacement(before, after)
        assert replacement is not None
        assert replacement.start_index == 0
        assert replacement.lines == ("@guard", "def f(x):")

    def test_two_separated_edits_become_one_run_carrying_the_middle_verbatim(self) -> None:
        before = "def f(x):\n    a = x\n    b = 1\n    c = x\n    return a, c"
        after = "def f(x):\n    a = esc(x)\n    b = 1\n    c = esc(x)\n    return a, c"
        replacement = line_replacement(before, after)
        assert replacement is not None
        assert (replacement.start_index, replacement.end_index) == (1, 3)
        assert replacement.lines[1] == "    b = 1"

    def test_a_deletion_leaves_an_empty_replacement(self) -> None:
        before = "def f(x):\n    eval(x)\n    return x"
        after = "def f(x):\n    return x"
        replacement = line_replacement(before, after)
        assert replacement is not None
        assert replacement.lines == ()
