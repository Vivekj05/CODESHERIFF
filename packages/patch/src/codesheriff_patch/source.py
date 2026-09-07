"""Reading a function with `ast`, and working out which lines a repair replaces.

Two jobs, kept together because both depend on the same fact about a `ChangeUnit`: `post_src` is
built by joining *whole lines* of the head file (`extraction/python.py`), so line `i` of `post_src`
is byte-identical to line `unit.start_line + i` of the file — leading indentation included. That is
what makes an anchored GitHub suggestion possible at all without fetching the file again.

It also means `post_src` is indented as it sits in the file, so a method's source does not parse on
its own. `dedented()` is what every parse here goes through, and nothing else compensates for it.

**`ast`, not tree-sitter, and not by oversight.** Extraction uses tree-sitter because it tolerates
the syntax errors a head commit frequently contains (§4). A syntax gate wants the opposite: a
parser that accepts a broken patch passes it, and the patch is then published as a suggestion a
reviewer can apply in one click. `ast.parse` refuses, and refusing is the entire job of the first
check. Nothing here executes the code — parsing is not running it.
"""

from __future__ import annotations

import ast
import builtins
import textwrap
from dataclasses import dataclass
from typing import Final

_BUILTINS: Final[frozenset[str]] = frozenset(dir(builtins))

STAR_IMPORT = "*"
"""Marker returned by `names_available_from` for a file containing `from x import *`.

A star import binds names this module cannot enumerate. Reporting only the names it can see would
make the free-name check confidently wrong in the one direction that matters — rejecting a draft
that references something the file really does have."""


def dedented(source: str) -> str:
    """`source` with its common leading indentation removed, so it can be parsed alone."""
    return textwrap.dedent(source)


def parse(source: str) -> ast.Module | None:
    """The parsed module, or None if it does not parse. Never raises, never executes."""
    try:
        return ast.parse(dedented(source))
    except (SyntaxError, ValueError):
        # ValueError covers source containing a null byte, which the compiler rejects separately
        # from a syntax error and which a model has no business producing.
        return None


@dataclass(frozen=True)
class Signature:
    """The part of a definition that its callers depend on.

    Defaults, annotations and the body are all absent. A repair is expected to change the body and
    may well tighten an annotation; what it may not do is change how the function is *called*,
    because the callers live in files this audit never fetched and the reviewer clicking "commit
    suggestion" sees only this hunk.
    """

    name: str
    parameters: tuple[str, ...]
    is_async: bool

    @classmethod
    def of(cls, node: ast.FunctionDef | ast.AsyncFunctionDef) -> Signature:
        args = node.args
        names = [
            *(a.arg for a in args.posonlyargs),
            *(a.arg for a in args.args),
            *([args.vararg.arg] if args.vararg else []),
            *(a.arg for a in args.kwonlyargs),
            *([args.kwarg.arg] if args.kwarg else []),
        ]
        return cls(
            name=node.name,
            parameters=tuple(names),
            is_async=isinstance(node, ast.AsyncFunctionDef),
        )


def signature_of(source: str) -> Signature | None:
    """The signature of the one function `source` defines, or None.

    None for source that does not parse, and for source whose module body is not exactly one
    function definition. Both are refusals rather than failures: a `<module>` unit legitimately has
    no signature, and a draft that turned one function into two has done something the caller of
    this module needs to decide about rather than something to be summarised as a name.
    """
    module = parse(source)
    if module is None or len(module.body) != 1:
        return None
    node = module.body[0]
    if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
        return None
    return Signature.of(node)


def bound_names(module: ast.Module) -> set[str]:
    """Every name `module` binds anywhere in it, scopes deliberately flattened.

    Flattening over-approximates: a name bound inside one function counts as bound in another. The
    error is one-directional and it is the safe direction — it can only make `free_names` report
    *fewer* free names, so the check built on it under-rejects rather than rejecting a correct
    patch. A real scope analysis belongs in the taint engine, which has one; this is a
    name-resolution sanity check, not an analysis.
    """
    names: set[str] = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store | ast.Del):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            names.add(node.name)
        elif isinstance(node, ast.ExceptHandler):
            # `except E as exc` binds `exc`; a bare `except E` binds nothing. Kept as its own
            # branch rather than folded in with the definitions above, because the guard is on
            # the value and not on the node type.
            if node.name:
                names.add(node.name)
        elif isinstance(node, ast.Global | ast.Nonlocal):
            names.update(node.names)
        elif isinstance(node, ast.Import | ast.ImportFrom):
            names.update(_names_bound_by_import(node))
    return names


def free_names(source: str) -> frozenset[str]:
    """Names `source` reads and never binds, excluding builtins.

    The root of an attribute chain counts, which is the case that matters: a draft calling
    `shlex.quote(...)` in a file that never imported `shlex` reads `shlex` free, and would raise
    `NameError` the first time the repaired line ran. That failure is invisible to a syntax check
    and to a reviewer skimming a green suggestion block.
    """
    module = parse(source)
    if module is None:
        return frozenset()
    bound = bound_names(module)
    used = {node.id for node in ast.walk(module) if isinstance(node, ast.Name)}
    return frozenset(used - bound - _BUILTINS)


def _names_bound_by_import(node: ast.Import | ast.ImportFrom) -> set[str]:
    """What an import statement makes available under a bare name.

    `import os.path` binds `os`, not `os.path` — the dotted form is reachable *through* the bound
    name. Getting that backwards would let a draft reference a submodule nothing imported.
    """
    names: set[str] = set()
    for alias in node.names:
        if alias.asname:
            names.add(alias.asname)
        elif isinstance(node, ast.Import):
            names.add(alias.name.split(".", 1)[0])
        else:
            names.add(alias.name)
    return names


def names_available_from(import_statements: list[str]) -> frozenset[str]:
    """Bare names the file's module-scope imports make available.

    `ChangeUnit.imports` holds import statements as written, because that is what the extractor
    saw. Re-parsing them here rather than storing bound names keeps the contract carrying what was
    in the file and this module carrying what it means.
    """
    names: set[str] = set()
    for statement in import_statements:
        try:
            parsed = ast.parse(textwrap.dedent(statement).strip())
        except (SyntaxError, ValueError):
            continue
        for node in ast.walk(parsed):
            if isinstance(node, ast.Import | ast.ImportFrom):
                names.update(_names_bound_by_import(node))
    return frozenset(names)


@dataclass(frozen=True)
class LineReplacement:
    """The contiguous run of lines a repair replaces, and what replaces them.

    Indices are 0-based into `post_src`'s lines. `absolute()` turns them into the file's own
    1-based line numbers, which is what a review comment anchors to.
    """

    start_index: int
    end_index: int
    """Inclusive. `start_index == end_index` replaces one line."""

    lines: tuple[str, ...]
    """The replacement, already carrying the file's absolute indentation — see the module
    docstring. Empty means the run is deleted outright, which is a legal suggestion."""

    def absolute(self, unit_start_line: int) -> tuple[int, int]:
        """`(start_line, end_line)`, 1-based and inclusive, in the head file."""
        return unit_start_line + self.start_index, unit_start_line + self.end_index

    @property
    def replaced_line_count(self) -> int:
        return self.end_index - self.start_index + 1


def line_replacement(before: str, after: str) -> LineReplacement | None:
    """The narrowest single run of lines whose replacement turns `before` into `after`.

    Narrowed from both ends rather than replacing the whole function, because the run has to lie
    inside the pull request's diff to be anchorable (D-095) and a whole-function span almost never
    does. A repair that touches two separated places produces one run spanning both, carrying the
    untouched lines between them verbatim — one suggestion, correct if applied, and honest about
    how much of the function it rewrites.

    Returns None when the two are identical: a draft that changed nothing is not a repair, and it
    is the shape a model returns when it has decided the code was fine.
    """
    b = before.splitlines()
    a = after.splitlines()
    if b == a or not b:
        return None

    prefix = 0
    while prefix < len(b) and prefix < len(a) and b[prefix] == a[prefix]:
        prefix += 1

    suffix = 0
    while (
        suffix < len(b) - prefix and suffix < len(a) - prefix and b[-1 - suffix] == a[-1 - suffix]
    ):
        suffix += 1

    start, end = prefix, len(b) - suffix  # `end` exclusive
    replacement = list(a[prefix : len(a) - suffix])

    if start == end:
        # A pure insertion replaces nothing, and GitHub cannot anchor a suggestion to zero lines.
        # Widen by one real line and carry it through unchanged, so the suggestion still describes
        # exactly the edit that was drafted.
        if start > 0:
            start -= 1
            replacement = [b[start], *replacement]
        else:
            end += 1
            replacement = [*replacement, b[0]]

    return LineReplacement(start_index=start, end_index=end - 1, lines=tuple(replacement))
