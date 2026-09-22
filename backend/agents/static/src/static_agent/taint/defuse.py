"""The def-use graph, built from the AST and built to be consumed.

The superseded version was regex over stripped lines, handled only single-target simple assignment,
and — the part that mattered — nothing ever queried it. `build_defuse_graph` was called, the result
was assigned to a local, and the local was never read again (`AUDIT.md` 3.1). What passed for taint
analysis was a nested loop over sources and sinks whose only reachability test was
`sink_line >= source_line`, so a source on line 2 and an unrelated sink on line 40 touching a
different variable produced a finding (`AUDIT.md` 3.2).

What is built here is a directed graph whose nodes are *definitions* and whose edges are *flows*.
`engine.py` propagates over it and asks `networkx` for real paths.

**Edges carry the sanitizer classes they clear.** That is the whole of the fix for `AUDIT.md` 3.4:
instead of "some sanitizer matched some line between the two", a path is valid for a sink when no
edge along it clears that sink's class. An `html.escape` is on the edge it actually wraps, and
clears `xss` there and nowhere else.

**A guard is a definition.** `if name not in ALLOWED: raise` produces a node that redefines `name`,
with an incoming edge clearing every class, so any later use resolves through it. That is what makes
validation flow-sensitive without a second analysis: the guard is simply where the variable's
current definition now lives.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import networkx as nx

from static_agent.taint.catalog import ALL_CLASSES, Catalog, RuleSink, SinkClass
from static_agent.taint.parse import field as ts_field
from static_agent.taint.parse import line_of, text_of, walk

PARAMETER_ORIGIN = "function_parameter"
"""The source rule id for a parameter of the analysed function.

Not in `sources.yml` because it is not a pattern. The unit of analysis is one function, so anything
arriving through its signature comes from code this analysis cannot see."""

RECEIVER_NAMES = frozenset({"self", "cls"})

EXIT_CALLEES = frozenset({"abort", "exit", "sys.exit", "fail", "PermissionDenied", "Http404"})
"""Calls that end the request in the way a `raise` does, for guard recognition."""

PATH_JOIN_CALLEES = frozenset(
    {"os.path.join", "path.join", "join", "posixpath.join", "Path", "PurePath"}
)


class FlowRole(StrEnum):
    SOURCE = "source"
    PROPAGATION = "propagation"
    GUARD = "guard"
    SINK = "sink"


@dataclass(frozen=True)
class FlowNode:
    """One point in the flow: where a value enters, is redefined, is validated, or is used."""

    node_id: str
    role: FlowRole
    name: str
    line: int
    expr: str
    origin_rule: str = ""
    sink_rule: RuleSink | None = None
    arg_index: int | None = None
    path_composed: bool = False


@dataclass
class DefUseGraph:
    """Definitions and the flows between them."""

    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    nodes: dict[str, FlowNode] = field(default_factory=dict)
    _counter: int = 0

    def add(self, node: FlowNode) -> str:
        self.nodes[node.node_id] = node
        self.graph.add_node(node.node_id)
        return node.node_id

    def next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}{self._counter}"

    def connect(
        self, src_id: str, dst_id: str, clears: frozenset[SinkClass], relation: str
    ) -> None:
        """One flow edge. `clears` is what a value stops being dangerous for along this hop."""
        self.graph.add_edge(src_id, dst_id, clears=clears, relation=relation)

    def origins(self) -> list[FlowNode]:
        return [n for n in self.nodes.values() if n.role is FlowRole.SOURCE]

    def sinks(self) -> list[FlowNode]:
        return [n for n in self.nodes.values() if n.role is FlowRole.SINK]


# ---------------------------------------------------------------------------------------------
# Expression inspection
# ---------------------------------------------------------------------------------------------


def _callee_text(call_node: Any, blob: bytes) -> str:
    fn = ts_field(call_node, "function")
    return text_of(fn, blob) if fn is not None else ""


def _is_callee_part(node: Any, root: Any) -> bool:
    """Whether `node` is part of the thing being called rather than an argument.

    `escape` in `escape(name)` is not a value flowing anywhere; `name` is. Without this every
    sanitizer and sink name would itself register as a variable use.
    """
    current = node
    parent = current.parent
    while parent is not None and parent.start_byte >= root.start_byte:
        if parent.type == "call":
            fn = ts_field(parent, "function")
            return fn is not None and (fn.start_byte, fn.end_byte) == (
                current.start_byte,
                current.end_byte,
            )
        if parent.type == "attribute":
            current, parent = parent, parent.parent
            continue
        return False
    return False


def _enclosing_sanitizer_classes(
    node: Any, root: Any, blob: bytes, catalog: Catalog, lang: str
) -> frozenset[SinkClass]:
    """The classes cleared by sanitizer calls that wrap this node.

    Computed per occurrence rather than per expression, so `foo(escape(a), b)` clears `xss` for `a`
    and nothing for `b`. Expression-level clearing was the shape of the old bug, one level down.
    """
    cleared: set[SinkClass] = set()
    current = node
    while current is not None and current.start_byte >= root.start_byte:
        if current.type == "call":
            callee = _callee_text(current, blob)
            for rule in catalog.sanitizers.get(lang, []):
                if rule.matches_callee(callee):
                    cleared |= rule.cleared_classes()
        if (current.start_byte, current.end_byte) == (root.start_byte, root.end_byte):
            break
        current = current.parent
    return frozenset(cleared)


def _is_path_composition(node: Any, blob: bytes) -> bool:
    """Whether this expression joins something onto a base path.

    Either an explicit join call, or a concatenation involving a string literal — which is what
    `UPLOAD_DIR + "/" + filename` is.
    """
    for found in walk(node):
        if found.type == "call":
            callee = _callee_text(found, blob)
            tail = callee.split(".")[-1] if callee else ""
            if callee in PATH_JOIN_CALLEES or tail in PATH_JOIN_CALLEES:
                return True
        if found.type == "binary_operator":
            operands = [c for c in found.children if c.type not in ("+",)]
            if any(c.type == "string" for c in operands) and len(operands) >= 2:
                return True
    return False


@dataclass(frozen=True)
class Contributor:
    """A value flowing into an expression, and what has been done to it on the way."""

    name: str
    clears: frozenset[SinkClass]
    source_rule: str = ""
    line: int = 0
    expr: str = ""


def contributors_of(expression: Any, blob: bytes, catalog: Catalog, lang: str) -> list[Contributor]:
    """Every variable use and every source expression inside `expression`.

    A source expression — `request.args.get("id")` — contributes under its own rule id rather than
    a variable name, because it is where untrusted data enters rather than something already
    tracked.
    """
    found: list[Contributor] = []
    seen_source_spans: set[tuple[int, int]] = set()

    for node in walk(expression):
        if node.type in ("attribute", "call", "subscript"):
            text = text_of(node, blob)
            for rule in catalog.sources.get(lang, []):
                if not rule.matches(text):
                    continue
                # Take the outermost match only: `request.args`, `request.args.get` and
                # `request.args.get("id")` are one entry point, not three.
                if any(
                    start <= node.start_byte and node.end_byte <= end
                    for start, end in seen_source_spans
                ):
                    break
                seen_source_spans.add((node.start_byte, node.end_byte))
                found.append(
                    Contributor(
                        name=text,
                        clears=_enclosing_sanitizer_classes(node, expression, blob, catalog, lang),
                        source_rule=rule.id,
                        line=line_of(node),
                        expr=text,
                    )
                )
                break

    for node in walk(expression):
        if node.type != "identifier" or _is_callee_part(node, expression):
            continue
        if any(
            start <= node.start_byte and node.end_byte <= end for start, end in seen_source_spans
        ):
            continue
        found.append(
            Contributor(
                name=text_of(node, blob),
                clears=_enclosing_sanitizer_classes(node, expression, blob, catalog, lang),
                line=line_of(node),
                expr=text_of(node, blob),
            )
        )
    return found


def keyword_arguments(call_node: Any, blob: bytes) -> dict[str, str]:
    """`{name: value_text}` for a call's keyword arguments.

    Read from the AST, so `subprocess.run(cmd,\\n    shell=True)` is seen. The old rules tested the
    same line only and missed exactly this (`AUDIT.md` 3.3).
    """
    args = ts_field(call_node, "arguments")
    if args is None:
        return {}
    keywords: dict[str, str] = {}
    for child in args.children:
        if child.type != "keyword_argument":
            continue
        name = ts_field(child, "name")
        value = ts_field(child, "value")
        if name is not None and value is not None:
            keywords[text_of(name, blob)] = text_of(value, blob)
    return keywords


def positional_arguments(call_node: Any, blob: bytes) -> list[Any]:
    """A call's positional argument nodes, in order."""
    args = ts_field(call_node, "arguments")
    if args is None:
        return []
    return [
        child
        for child in args.children
        if child.type not in ("(", ")", ",", "keyword_argument", "comment")
    ]


# ---------------------------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------------------------


def _condition_validates(condition: Any, blob: bytes) -> set[str]:
    """Names this condition *validates*, as opposed to merely testing for emptiness.

    The distinction is load-bearing. `if blob is None: return None` is a null check on a value that
    is still exactly as tainted afterwards; `if name not in ALLOWED: raise` and
    `if not is_public(url): abort()` have established something about the value. Treating the first
    as a guard silently suppresses `cwe-502-cache-get`, whose vulnerable member opens with one.

    So a name counts as validated only when it appears **inside a call** or as an operand of a
    membership test — never as a bare operand of a comparison.
    """
    validated: set[str] = set()

    for node in walk(condition):
        if node.type == "comparison_operator":
            if not any(child.type in ("in", "not in") for child in node.children):
                continue
            for child in node.children:
                if child.type == "identifier" or child.type in ("attribute", "subscript"):
                    validated.add(text_of(child, blob))

        if node.type == "call":
            for argument in positional_arguments(node, blob):
                for inner in walk(argument):
                    if inner.type == "identifier" and not _is_callee_part(inner, argument):
                        validated.add(text_of(inner, blob))

    return validated


def _block_exits(block: Any, blob: bytes) -> bool:
    """Whether this branch stops the function rather than falling through."""
    for node in walk(block):
        if node.type in ("raise_statement", "return_statement"):
            return True
        if node.type == "call":
            callee = _callee_text(node, blob)
            if callee in EXIT_CALLEES or callee.split(".")[-1] in EXIT_CALLEES:
                return True
    return False


# ---------------------------------------------------------------------------------------------
# The builder
# ---------------------------------------------------------------------------------------------


class GraphBuilder:
    """Walks a function body in order, maintaining the current definition of each name."""

    def __init__(self, root: Any, blob: bytes, catalog: Catalog, lang: str) -> None:
        self.root = root
        self.blob = blob
        self.catalog = catalog
        self.lang = lang
        self.dug = DefUseGraph()
        self.last_def: dict[str, str] = {}

    # -- helpers ------------------------------------------------------------------------------

    def _link_contributors(
        self, contributors: list[Contributor], target_id: str, relation: str
    ) -> None:
        """Draw an edge into `target_id` for every contributor that is already tracked."""
        for contributor in contributors:
            if contributor.source_rule:
                origin_id = self.dug.add(
                    FlowNode(
                        node_id=self.dug.next_id("src"),
                        role=FlowRole.SOURCE,
                        name=contributor.name,
                        line=contributor.line,
                        expr=contributor.expr,
                        origin_rule=contributor.source_rule,
                    )
                )
                self.dug.connect(origin_id, target_id, contributor.clears, relation)
                continue

            known = self.last_def.get(contributor.name)
            if known is not None:
                self.dug.connect(known, target_id, contributor.clears, relation)

    def _define(self, name: str, node: Any, value: Any | None) -> None:
        expression = value if value is not None else node
        contributors = contributors_of(expression, self.blob, self.catalog, self.lang)
        def_id = self.dug.add(
            FlowNode(
                node_id=self.dug.next_id("def"),
                role=FlowRole.PROPAGATION,
                name=name,
                line=line_of(node),
                expr=text_of(node, self.blob).strip(),
                path_composed=_is_path_composition(expression, self.blob),
            )
        )
        self._link_contributors(contributors, def_id, "assign")
        self.last_def[name] = def_id

    # -- seeding ------------------------------------------------------------------------------

    def seed_parameters(self, function_node: Any) -> None:
        """Every parameter except the receiver becomes an origin."""
        params = ts_field(function_node, "parameters")
        if params is None:
            return
        for child in params.children:
            name_node = child
            if child.type in ("default_parameter", "typed_parameter", "typed_default_parameter"):
                name_node = ts_field(child, "name") or next(
                    (c for c in child.children if c.type == "identifier"), None
                )
            elif child.type in ("list_splat_pattern", "dictionary_splat_pattern"):
                name_node = next((c for c in child.children if c.type == "identifier"), None)
            elif child.type != "identifier":
                continue
            if name_node is None or name_node.type != "identifier":
                continue

            name = text_of(name_node, self.blob)
            if name in RECEIVER_NAMES:
                continue
            origin_id = self.dug.add(
                FlowNode(
                    node_id=self.dug.next_id("src"),
                    role=FlowRole.SOURCE,
                    name=name,
                    line=line_of(name_node),
                    expr=f"parameter {name}",
                    origin_rule=PARAMETER_ORIGIN,
                )
            )
            self.last_def[name] = origin_id

    # -- statement walking --------------------------------------------------------------------

    def visit(self, node: Any) -> None:
        """Walk a block's statements in order. Order is what makes guards work."""
        for statement in node.children:
            self.visit_statement(statement)

    def visit_statement(self, statement: Any) -> None:
        # Sinks first, against the definitions in force *before* this statement rebinds
        # anything — otherwise `x = sanitize(x)` would be read as sanitising the use in its
        # own right-hand side.
        self.scan_sinks(statement)

        kind = statement.type
        if kind == "expression_statement":
            for child in statement.children:
                self.visit_statement_inner(child)
        else:
            self.visit_statement_inner(statement)

    def visit_statement_inner(self, statement: Any) -> None:
        kind = statement.type

        if kind in ("assignment", "augmented_assignment"):
            self.handle_assignment(statement)
        elif kind == "with_statement":
            self.handle_with(statement)
        elif kind == "if_statement":
            self.handle_if(statement)
        elif kind in ("for_statement", "while_statement"):
            self.handle_loop(statement)
        elif kind in ("try_statement", "with_clause", "block", "else_clause", "except_clause"):
            for child in statement.children:
                self.visit_statement(child)
        elif kind in ("function_definition", "decorated_definition", "class_definition"):
            # A nested definition is a different scope with its own parameters. The unit is the
            # outermost function (D-049), so its body is not part of this flow.
            return

    def handle_assignment(self, statement: Any) -> None:
        left = ts_field(statement, "left")
        right = ts_field(statement, "right")
        if left is None:
            return
        value = right if right is not None else statement

        targets = (
            [c for c in left.children if c.type == "identifier"]
            if left.type in ("pattern_list", "tuple_pattern")
            else [left]
        )
        for target in targets:
            if target.type == "identifier":
                self._define(text_of(target, self.blob), statement, value)
            elif target.type in ("attribute", "subscript"):
                # `self.cache[key] = value` — tracked under its full text, so a later read of the
                # same expression resolves to it.
                self._define(text_of(target, self.blob), statement, value)

    def handle_with(self, statement: Any) -> None:
        for clause in statement.children:
            if clause.type != "with_clause":
                continue
            for item in clause.children:
                if item.type != "with_item":
                    continue
                value = ts_field(item, "value") or item
                if value.type == "as_pattern":
                    bound = next((c for c in value.children if c.type == "as_pattern_target"), None)
                    produced = value.children[0] if value.children else value
                    if bound is not None:
                        self._define(text_of(bound, self.blob), item, produced)
        body = ts_field(statement, "body")
        if body is not None:
            self.visit(body)

    def handle_if(self, statement: Any) -> None:
        condition = ts_field(statement, "condition")
        consequence = ts_field(statement, "consequence")

        exits = consequence is not None and _block_exits(consequence, self.blob)
        if condition is not None and exits:
            for name in _condition_validates(condition, self.blob):
                known = self.last_def.get(name)
                if known is None:
                    continue
                guard_id = self.dug.add(
                    FlowNode(
                        node_id=self.dug.next_id("guard"),
                        role=FlowRole.GUARD,
                        name=name,
                        line=line_of(condition),
                        expr=text_of(condition, self.blob).strip(),
                    )
                )
                # Clears every class: the function refused to continue unless the value passed,
                # and this analysis cannot know which property was checked. A guard that does not
                # actually validate is a false negative, and the corpus is what measures it.
                self.dug.connect(known, guard_id, ALL_CLASSES, "guard")
                self.last_def[name] = guard_id

        for child in statement.children:
            if child.type in ("block", "elif_clause", "else_clause"):
                self.visit_statement(child)

    def handle_loop(self, statement: Any) -> None:
        left = ts_field(statement, "left")
        right = ts_field(statement, "right")
        if left is not None and right is not None and left.type == "identifier":
            self._define(text_of(left, self.blob), statement, right)
        body = ts_field(statement, "body")
        if body is not None:
            self.visit(body)

    # -- sinks --------------------------------------------------------------------------------

    def scan_sinks(self, statement: Any) -> None:
        """Record every dangerous argument of every matching call in this statement."""
        for node in walk(statement):
            if node.type != "call":
                continue
            callee = _callee_text(node, self.blob)
            if not callee:
                continue
            keywords = keyword_arguments(node, self.blob)
            positionals = positional_arguments(node, self.blob)

            for rule in self.catalog.sinks.get(self.lang, []):
                if not rule.matches_callee(callee) or not rule.keywords_allow(keywords):
                    continue
                for index in rule.args:
                    if index >= len(positionals):
                        continue
                    argument = positionals[index]
                    contributors = contributors_of(argument, self.blob, self.catalog, self.lang)
                    if not contributors:
                        continue
                    sink_id = self.dug.add(
                        FlowNode(
                            node_id=self.dug.next_id("sink"),
                            role=FlowRole.SINK,
                            name=rule.id,
                            line=line_of(node),
                            expr=text_of(node, self.blob).strip(),
                            sink_rule=rule,
                            arg_index=index,
                            path_composed=_is_path_composition(argument, self.blob),
                        )
                    )
                    self._link_contributors(contributors, sink_id, "argument")


def build_defuse_graph(root: Any, blob: bytes, catalog: Catalog, lang: str) -> DefUseGraph:
    """The def-use graph for one function, ready to propagate over."""
    from static_agent.taint.parse import enclosing_function

    function_node = enclosing_function(root)
    builder = GraphBuilder(root, blob, catalog, lang)
    builder.seed_parameters(function_node)

    body = ts_field(function_node, "body")
    builder.visit(body if body is not None else function_node)
    return builder.dug
