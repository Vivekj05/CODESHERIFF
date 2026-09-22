"""tree-sitter over one whole Python file.

Whole file, never a diff fragment. The parser is handed exactly the bytes GitHub serves for the
blob, so a node's line numbers *are* the file's line numbers and no offset arithmetic stands
between a reported line and the line a reviewer opens.

There is no `except Exception: return None` fallback here, and no regex path behind one. The
superseded `static_agent/taint/parse.py` had both: a failed parse silently became a one-node
"module" covering the whole file, and a failed symbol walk silently became a regex scan for `def`.
Either turns a broken deployment into a system that reports silence, which is `AUDIT.md` 4.4 in
another package. tree-sitter tolerates syntax errors natively — it produces ERROR nodes and keeps
the surrounding tree — so the only failure left is a missing language pack, which is a deployment
fault and must be loud.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

_LANGUAGE = "python"

_parser: Any | None = None


def _parser_for_python() -> Any:
    """One parser per process. Building it costs more than parsing a file does."""
    global _parser
    if _parser is None:
        import tree_sitter_language_pack as tslp

        _parser = tslp.get_parser(_LANGUAGE)
    return _parser


@dataclass(frozen=True)
class PythonSymbol:
    """One outermost function or method, with its exact source.

    "Outermost" means a nested `def` is part of its parent's source rather than a unit of its own.
    A closure's free variables are bound outside it, so a unit containing only the closure is a
    fragment whose taint sources are invisible — the shape of `AUDIT.md` 4.2 arrived at from the
    other direction.
    """

    name: str
    enclosing_class: str | None
    """Innermost enclosing class. `ChangeUnit` carries one level, so `Outer.Inner.m` qualifies as
    `Inner.m`; the file path already distinguishes it from any other `Inner`."""

    decorators: tuple[str, ...]
    start_line: int
    """1-based, and the *decorator's* line when the function is decorated. A PR that deletes
    `@login_required` changes a line inside this span, which is what makes that deletion
    attributable to the function it guarded (D-013)."""

    end_line: int
    """1-based, inclusive."""

    source: str
    """Whole lines from `start_line` to `end_line`. Sliced by line rather than by byte offset so a
    method keeps the indentation it is written with — a byte slice starts at the `def` keyword and
    silently dedents the first line only."""

    def contains(self, line: int) -> bool:
        return self.start_line <= line <= self.end_line


@dataclass(frozen=True)
class PythonFile:
    """What one parsed file offers the unit builder."""

    symbols: tuple[PythonSymbol, ...]
    imports: tuple[str, ...]
    """Module-scope import statements, as written. Imports inside a function body are excluded:
    they belong to that function's source, which the agent already receives in full."""

    def symbol_for(self, line: int) -> PythonSymbol | None:
        """The function owning `line`, or None when the line is at module scope."""
        for symbol in self.symbols:
            if symbol.contains(line):
                return symbol
        return None


def parse_python_file(source: str) -> PythonFile:
    """Parse one file's full text into its outermost functions and module-scope imports."""
    data = source.encode("utf-8")
    tree = _parser_for_python().parse(data)
    lines = source.splitlines()

    symbols: list[PythonSymbol] = []
    imports: list[str] = []
    _walk(tree.root_node, data, lines, enclosing_class=None, symbols=symbols, imports=imports)
    return PythonFile(symbols=tuple(symbols), imports=tuple(imports))


def _walk(
    node: Any,
    data: bytes,
    lines: list[str],
    *,
    enclosing_class: str | None,
    symbols: list[PythonSymbol],
    imports: list[str],
) -> None:
    """Descend everywhere except into a function body.

    Stopping at a function is what makes the outermost function the unit. Descending through
    everything else means a `def` guarded by `if TYPE_CHECKING:` or defined inside a `try:` is
    still found — those are ordinary Python, and a walk that only looked at direct module children
    would miss them without ever saying so.
    """
    for child in node.children:
        kind = child.type

        if kind in {"import_statement", "import_from_statement"}:
            imports.append(_text(child, data))

        elif kind == "function_definition":
            symbols.append(_symbol(child, child, data, lines, enclosing_class))

        elif kind == "decorated_definition":
            definition = child.child_by_field_name("definition")
            if definition is None:
                continue
            if definition.type == "function_definition":
                # The span is the decorated node's, so it starts at the first decorator.
                symbols.append(_symbol(definition, child, data, lines, enclosing_class))
            else:
                _walk(
                    definition,
                    data,
                    lines,
                    enclosing_class=_name_of(definition, data) or enclosing_class,
                    symbols=symbols,
                    imports=imports,
                )

        elif kind == "class_definition":
            _walk(
                child,
                data,
                lines,
                enclosing_class=_name_of(child, data) or enclosing_class,
                symbols=symbols,
                imports=imports,
            )

        else:
            _walk(
                child,
                data,
                lines,
                enclosing_class=enclosing_class,
                symbols=symbols,
                imports=imports,
            )


def _symbol(
    definition: Any,
    span: Any,
    data: bytes,
    lines: list[str],
    enclosing_class: str | None,
) -> PythonSymbol:
    """`definition` names the function; `span` is what the unit covers, decorators included."""
    start_line = span.start_point[0] + 1
    end_line = span.end_point[0] + 1
    return PythonSymbol(
        name=_name_of(definition, data) or "<anonymous>",
        enclosing_class=enclosing_class,
        decorators=tuple(
            _decorator_name(child, data) for child in span.children if child.type == "decorator"
        ),
        start_line=start_line,
        end_line=end_line,
        source="\n".join(lines[start_line - 1 : end_line]),
    )


def _decorator_name(node: Any, data: bytes) -> str:
    """A decorator as written, without the `@` and on one line.

    The arguments are kept. `@require_role("admin")` and `@require_role("viewer")` are different
    guards, and dropping to the bare name would make a PR that weakens one look identical to a PR
    that changes nothing. Whitespace is collapsed only so a decorator wrapped across lines is one
    string; nothing is truncated.
    """
    return " ".join(_text(node, data).lstrip("@").split())


def _name_of(node: Any, data: bytes) -> str | None:
    name = node.child_by_field_name("name")
    return _text(name, data) if name is not None else None


def _text(node: Any, data: bytes) -> str:
    """Decode one node from the file's bytes.

    The whole file is encoded once, in `parse_python_file`. tree-sitter offsets are byte offsets,
    so re-encoding per node would be both wasteful and a chance to encode differently.
    """
    return data[node.start_byte : node.end_byte].decode("utf-8", errors="replace")
