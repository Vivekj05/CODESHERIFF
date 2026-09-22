"""The tree-sitter layer the analysis actually runs on.

`symbols.py` and `ASTNodeView` are gone. The mirror tree was built on every parse and never read —
tree-sitter was wired correctly and unreachable, reached only from a literal `if False` branch
(`AUDIT.md` 3.1) — and `extract_symbols` fed a `enclosing_symbol()` that could therefore only ever
return `None`. The engine now works on real nodes, so what is tested here is what it uses.
"""

from __future__ import annotations

import pytest

from static_agent.taint.parse import (
    UnsupportedLanguageError,
    enclosing_function,
    field,
    language_key,
    line_of,
    parse,
    text_of,
)


def test_python_aliases_resolve_to_one_key() -> None:
    assert language_key("Python") == language_key("py") == "python"


@pytest.mark.parametrize("language", ["javascript", "typescript", "js", "ts", "cobol", "go"])
def test_every_other_language_raises(language: str) -> None:
    """Everything the engine does is Python-shaped, so a wrong answer is worth less than none."""
    with pytest.raises(UnsupportedLanguageError):
        language_key(language)


def test_parse_returns_a_tree_and_the_bytes_it_indexes() -> None:
    root, blob = parse("def hello():\n    return 'world'\n", "python")

    assert root.type == "module"
    assert text_of(root, blob).startswith("def hello()")


def test_text_is_sliced_from_bytes_not_characters() -> None:
    """tree-sitter's offsets are byte offsets; slicing the `str` gives the wrong span as soon as
    the source contains a non-ASCII character."""
    source = "def greet():\n    return 'café — ready'\n"
    root, blob = parse(source, "python")
    strings = [n for n in root.children[0].children if n.type == "block"]
    body_text = text_of(strings[0], blob)

    assert "café — ready" in body_text


def test_lines_are_one_based() -> None:
    root, _ = parse("x = 1\ny = 2\n", "python")
    assert line_of(root.children[0]) == 1
    assert line_of(root.children[1]) == 2


def test_fields_are_addressed_by_name_not_index() -> None:
    """Index-based access breaks the moment a decorator or an annotation appears."""
    root, blob = parse("value = compute(a, b)\n", "python")
    assignment = root.children[0]

    assert text_of(field(assignment, "left"), blob) == "value"
    assert text_of(field(assignment, "right"), blob) == "compute(a, b)"


def test_the_enclosing_function_is_found_through_its_decorators() -> None:
    """Decorator removal is the entire signal for the access-control CWEs (D-013), so a decorated
    function must not read as having no parameters."""
    root, blob = parse("@login_required\ndef handle(request, uid):\n    return uid\n", "python")
    function = enclosing_function(root)

    assert function.type == "function_definition"
    assert text_of(field(function, "name"), blob) == "handle"


def test_a_module_scope_unit_has_no_enclosing_function() -> None:
    """A `<module>` unit carries a whole file (D-049) and has no parameters to treat as sources."""
    root, _ = parse("API_KEY = 'sk_live_x'\n", "python")
    assert enclosing_function(root).type == "module"


def test_broken_syntax_still_parses() -> None:
    """The reason tree-sitter is used over the built-in `ast` (§5): pull request heads frequently
    contain syntax errors, and an analysis that cannot open the file reports nothing."""
    root, blob = parse("def handle(request:\n    os.system(request.args['c']\n", "python")

    assert root is not None
    assert "os.system" in text_of(root, blob)
