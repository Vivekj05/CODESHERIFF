"""Tree-sitter access for the taint engine.

This used to mirror the whole tree into a pydantic `ASTNodeView` on every parse, and then the
analysis never used it — tree-sitter was wired correctly and unreachable, called only from a dead
`if False` branch (`AUDIT.md` 3.1, 3.3). The engine now works on real tree-sitter nodes, so what is
left here is the parser cache and the handful of helpers the graph builder needs.

Nodes are addressed through `child_by_field_name`, not by child index. `call` has `function` and
`arguments`; `assignment` has `left` and `right`; `if_statement` has `condition` and `consequence`.
Index-based access breaks the moment a decorator, a type annotation or a comment appears.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

PYTHON_ALIASES = frozenset({"python", "py"})


class UnsupportedLanguageError(ValueError):
    """The taint engine has no model for this language."""


class ParseError(RuntimeError):
    """tree-sitter could not be loaded, or produced no tree."""


_PARSERS: dict[str, Any] = {}


def language_key(language: str) -> str:
    """The catalog key for a `ChangeUnit.language`, or raise.

    JavaScript and TypeScript raise rather than falling through to the Python model. Everything the
    engine does below — argument positions, keyword arguments, `with` handling, guard recognition —
    is Python-shaped, and running it on a JavaScript tree produces confident nonsense. The old
    engine did exactly that with regexes, which is how the JS `\\beval` rule came to match the
    identifier `evaluate` (`AUDIT.md` 3.3).
    """
    key = language.strip().lower()
    if key in PYTHON_ALIASES:
        return "python"
    raise UnsupportedLanguageError(language)


def get_parser(lang_key: str) -> Any:
    """A cached tree-sitter parser. Raises `ParseError` if the grammar will not load."""
    if lang_key in _PARSERS:
        return _PARSERS[lang_key]
    try:
        import tree_sitter_language_pack as tslp

        parser = tslp.get_parser(lang_key)
    except Exception as exc:  # pragma: no cover - depends on the wheel being installed
        raise ParseError(f"could not load a tree-sitter parser for {lang_key}: {exc}") from exc
    _PARSERS[lang_key] = parser
    return parser


def parse(source: str, lang_key: str) -> tuple[Any, bytes]:
    """The root node and the source bytes it indexes into.

    The bytes are returned rather than re-encoded per node because every text lookup slices them,
    and tree-sitter's offsets are byte offsets — slicing the `str` gives the wrong span the moment
    the file contains a non-ASCII character.
    """
    blob = source.encode("utf-8")
    tree = get_parser(lang_key).parse(blob)
    if tree is None or tree.root_node is None:
        raise ParseError("tree-sitter returned no tree")
    return tree.root_node, blob


def text_of(node: Any, blob: bytes) -> str:
    """The source text a node spans."""
    return blob[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def line_of(node: Any) -> int:
    """1-based line of a node's first character."""
    return int(node.start_point[0]) + 1


def field(node: Any, name: str) -> Any | None:
    """`child_by_field_name`, tolerating grammars that do not define the field."""
    try:
        return node.child_by_field_name(name)
    except Exception:  # pragma: no cover - defensive against grammar differences
        return None


def walk(node: Any) -> Any:
    """Every node in the subtree, parents before children."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def descendants_of_type(node: Any, *types: str) -> list[Any]:
    """Every node of the given types in the subtree, in document order."""
    wanted = frozenset(types)
    return [found for found in walk(node) if found.type in wanted]


def enclosing_function(root: Any) -> Any:
    """The outermost `function_definition` in the tree, or the tree itself.

    A `ChangeUnit` is already one function (D-049), so this normally finds it immediately. A
    `<module>` unit carries a whole file and has none, in which case the module node is the scope —
    which is right, because a module-scope change has no parameters to treat as sources.
    """
    for node in root.children:
        if node.type in ("function_definition", "decorated_definition"):
            if node.type == "decorated_definition":
                for child in node.children:
                    if child.type == "function_definition":
                        return child
            return node
    return root
