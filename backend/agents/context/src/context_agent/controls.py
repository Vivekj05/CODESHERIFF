"""What a function does to guard itself, read off the syntax tree.

A control is a decorator or a call. That is the whole vocabulary, and it is deliberately not
a list of security-sounding names: which controls matter is decided by the repository's own
history in `regression.py`, not here. This module only answers "what does this source apply
to itself", for a unit and for a precedent excerpt alike — the two have to be read the same
way or a control could go missing purely by which side of the comparison it sat on.

**tree-sitter, not substrings** (`AUDIT.md` 3.7, and the same mistake as 3.3). The superseded
analyzer recovered decorators by scanning source text for `@require_csrf_token`, which finds
the string in a comment, in a docstring, and in a variable named `has_require_csrf_token`. It
also cannot tell a decorator on the function from a decorator on a nested helper. Both of
those turn into findings that are wrong in a way no amount of tuning fixes.

Names are normalised to their **dotted callee**, then compared on the last segment when a CWE
is being chosen (`classify.py`). `@require_owner("attachment_id")` and `@require_owner` are
the same control applied with different arguments, and a repository that tightens an argument
has not removed a guard.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)

PYTHON_ALIASES = frozenset({"python", "py"})

_PARSERS: dict[str, Any] = {}


class UnsupportedLanguageError(ValueError):
    """No control model for this language.

    Raised rather than falling through to the Python reader. Decorators and entry guards are
    Python-shaped; running this over a JavaScript tree yields confident nonsense, which is
    precisely how the superseded static agent's `\\beval` rule came to match `evaluate`.
    """


class ParseError(RuntimeError):
    """tree-sitter could not be loaded, or produced no tree."""


class ControlKind(StrEnum):
    """How a control is applied. Kept distinct so an explanation can say which."""

    DECORATOR = "decorator"
    GUARD_CALL = "call"


@dataclass(frozen=True)
class Control:
    """One decorator or one call, by name.

    Frozen and hashable because the whole comparison downstream is set arithmetic: what this
    repository established, minus what this unit applies.
    """

    kind: ControlKind
    name: str
    """The dotted callee — `admin_required`, `app.route`, `self.repo.save`."""

    @property
    def simple_name(self) -> str:
        """The last dotted segment, which is where a function's intent lives.

        `Note.query.get_or_404` is a lookup called `get_or_404`; classifying on the full
        dotted path would let the receiver's name decide the CWE, and receivers are named
        after data rather than after what is being enforced.
        """
        return self.name.rsplit(".", 1)[-1]

    def describe(self) -> str:
        return f"@{self.name}" if self.kind is ControlKind.DECORATOR else f"{self.name}()"


def language_key(language: str) -> str:
    """The tree-sitter catalog key for a `ChangeUnit.language`, or raise."""
    key = language.strip().lower()
    if key in PYTHON_ALIASES:
        return "python"
    raise UnsupportedLanguageError(language)


def _get_parser(lang_key: str) -> Any:
    if lang_key in _PARSERS:
        return _PARSERS[lang_key]
    try:
        import tree_sitter_language_pack as tslp

        parser = tslp.get_parser(lang_key)
    except Exception as exc:  # pragma: no cover - depends on the wheel being installed
        raise ParseError(f"could not load a tree-sitter parser for {lang_key}: {exc}") from exc
    _PARSERS[lang_key] = parser
    return parser


def _text(node: Any, blob: bytes) -> str:
    """The source a node spans.

    Sliced from bytes because tree-sitter's offsets are byte offsets; slicing the `str`
    gives the wrong span the moment the file holds a non-ASCII character.
    """
    return blob[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _walk(node: Any) -> Any:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(current.children))


def _dotted_name(node: Any, blob: bytes) -> str | None:
    """The callee name of an expression, with any call arguments stripped.

    `require_owner` from `require_owner("attachment_id")`, `app.route` from
    `app.route("/x")`, `self.repo.save` from `self.repo.save(team)`. Returns None for
    anything that is not a name — a lambda decorator or a subscript is not a control this
    agent can reason about, and inventing a name for it would create a control that can
    never be matched on the other side of the comparison.

    Reassembled from name segments rather than sliced out of the source, so a chained call
    yields the method that is actually being invoked. Slicing gave
    `Query.filter(x >= y).all` for `.all()` at the end of a chain, which is a name no other
    excerpt can ever produce — every such call would read as a control unique to one
    function, and enough of them in one repository would start inventing conventions out of
    query-builder chains.
    """
    current = node
    while current is not None and current.type == "call":
        current = current.child_by_field_name("function")
    if current is None:
        return None

    if current.type in {"identifier", "dotted_name"}:
        return _text(current, blob).strip()

    if current.type == "attribute":
        attribute = current.child_by_field_name("attribute")
        if attribute is None:
            return None
        tail = _text(attribute, blob).strip()
        receiver = current.child_by_field_name("object")
        head = _dotted_name(receiver, blob) if receiver is not None else None
        # An unnameable receiver — a call, a subscript, a literal — contributes nothing,
        # and the method name alone is the part two excerpts can agree on.
        return f"{head}.{tail}" if head else tail

    return None


def _outermost_function(root: Any) -> Any | None:
    """The unit's own definition — never a nested one (D-049).

    A closure's decorators guard the closure, not the function the change is about, and a
    guard call inside a nested helper does not run when the outer function is called.
    """
    for node in _walk(root):
        if node.type in {"function_definition", "decorated_definition"}:
            return node
    return None


def _definition_of(node: Any) -> Any:
    if node.type != "decorated_definition":
        return node
    return node.child_by_field_name("definition") or node


def control_surface(source: str, language: str = "python") -> frozenset[Control]:
    """Every decorator and every call the outermost function in `source` applies.

    Read identically for a change unit and for a precedent excerpt. A precedent excerpt is a
    single merged function, which is what `apps/worker` writes and what a corpus history
    holds, so the same "outermost definition" rule addresses the right node in both.

    Returns an empty set for source that holds no function at all rather than raising:
    tree-sitter tolerates broken syntax and a `<module>` unit is a legitimate unit with no
    decorators to read.
    """
    lang_key = language_key(language)
    blob = source.encode("utf-8")
    tree = _get_parser(lang_key).parse(blob)
    if tree is None or tree.root_node is None:
        raise ParseError("tree-sitter returned no tree")

    outer = _outermost_function(tree.root_node)
    if outer is None:
        return frozenset()

    found: set[Control] = set()

    if outer.type == "decorated_definition":
        for child in outer.children:
            if child.type != "decorator":
                continue
            # A `decorator` node spans the `@` as well, so descend to the expression.
            expression = next((c for c in child.children if c.type != "@"), None)
            if expression is None:
                continue
            if name := _dotted_name(expression, blob):
                found.add(Control(ControlKind.DECORATOR, name))

    body = _definition_of(outer).child_by_field_name("body")
    if body is not None:
        for node in _walk(body):
            if node.type != "call":
                continue
            if name := _dotted_name(node, blob):
                found.add(Control(ControlKind.GUARD_CALL, name))

    return frozenset(found)
