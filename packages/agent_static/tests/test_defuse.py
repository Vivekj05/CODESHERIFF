"""The def-use graph, tested as a graph.

The superseded test asserted `len(g.nodes) > 0` on a graph nothing ever read, which is precisely
why `AUDIT.md` 3.1 went unnoticed: the builder could have returned anything and the suite would
have agreed. These tests ask what the edges say.
"""

from __future__ import annotations

from typing import Any

from static_agent.config import StaticConfig
from static_agent.taint.catalog import Catalog, SinkClass
from static_agent.taint.defuse import PARAMETER_ORIGIN, DefUseGraph, FlowRole, build_defuse_graph
from static_agent.taint.parse import parse

CATALOG = Catalog.load_from_dir(StaticConfig().rules_dir)


def graph_for(source: str) -> DefUseGraph:
    root, blob = parse(source, "python")
    return build_defuse_graph(root, blob, CATALOG, "python")


def edge_clears(dug: DefUseGraph) -> list[frozenset[Any]]:
    return [data["clears"] for _, _, data in dug.graph.edges(data=True)]


def test_parameters_become_origins() -> None:
    dug = graph_for("def handle(self, term, limit=10):\n    return term\n")
    origins = {node.name: node for node in dug.origins()}

    assert set(origins) == {"term", "limit"}, "self is the receiver, not an argument"
    assert all(node.origin_rule == PARAMETER_ORIGIN for node in origins.values())


def test_a_source_expression_becomes_an_origin() -> None:
    dug = graph_for("def handle(request):\n    uid = request.args['id']\n")
    rules = {node.origin_rule for node in dug.origins()}

    assert "http.flask_request" in rules


def test_an_assignment_links_its_right_hand_side_to_its_target() -> None:
    dug = graph_for(
        "def handle(request):\n"
        "    uid = request.args['id']\n"
        "    query = f'SELECT {uid}'\n"
        "    cursor.execute(query)\n"
    )
    # origin -> uid -> query -> sink, so the sink is reachable and three hops away.
    sinks = dug.sinks()
    assert len(sinks) == 1
    import networkx as nx

    origin = next(node for node in dug.origins() if node.origin_rule.startswith("http"))
    path = nx.shortest_path(dug.graph, origin.node_id, sinks[0].node_id)
    assert len(path) == 4


def test_an_unconnected_sink_has_no_path_from_any_origin() -> None:
    """`AUDIT.md` 3.2: the old engine paired every source with every later sink."""
    import networkx as nx

    dug = graph_for(
        "def handle(request):\n"
        "    name = request.args['name']\n"
        "    audit_log(name)\n"
        "    os.system(BACKUP_COMMAND)\n"
    )
    assert dug.sinks() == [] or all(
        not any(nx.has_path(dug.graph, origin.node_id, sink.node_id) for origin in dug.origins())
        for sink in dug.sinks()
    )


def test_a_sanitizer_edge_carries_only_the_classes_it_clears() -> None:
    """`AUDIT.md` 3.4. `clears` was declared and never read."""
    dug = graph_for(
        "def handle(request):\n    name = request.args['name']\n    page = escape(name)\n"
    )
    cleared = set().union(*edge_clears(dug)) if edge_clears(dug) else set()

    assert SinkClass.XSS in cleared
    assert SinkClass.COMMAND not in cleared


def test_a_coercion_edge_clears_every_class() -> None:
    dug = graph_for("def handle(request):\n    uid = int(request.args['id'])\n")
    cleared = set().union(*edge_clears(dug)) if edge_clears(dug) else set()

    assert cleared == set(SinkClass)


def test_a_sanitizer_wrapping_one_argument_does_not_clear_the_other() -> None:
    """Computed per occurrence, not per expression."""
    dug = graph_for(
        "def handle(request):\n"
        "    a = request.args['a']\n"
        "    b = request.args['b']\n"
        "    page = render(escape(a), b)\n"
    )
    by_target = {}
    for src, dst, data in dug.graph.edges(data=True):
        by_target.setdefault(dug.nodes[dst].name, []).append((dug.nodes[src].name, data["clears"]))

    page_edges = dict(by_target.get("page", []))
    assert SinkClass.XSS in page_edges["a"]
    assert SinkClass.XSS not in page_edges["b"]


def test_a_validating_guard_becomes_a_definition() -> None:
    """A guard is where the variable's current definition now lives, which is what makes
    validation flow-sensitive without a second analysis."""
    dug = graph_for(
        "def handle(name):\n"
        "    if name not in ALLOWED:\n"
        "        raise KeyError(name)\n"
        "    return name\n"
    )
    guards = [node for node in dug.nodes.values() if node.role is FlowRole.GUARD]

    assert len(guards) == 1
    assert guards[0].name == "name"


def test_a_null_check_is_not_a_guard() -> None:
    dug = graph_for(
        "def handle(blob):\n    if blob is None:\n        return None\n    return blob\n"
    )
    assert [node for node in dug.nodes.values() if node.role is FlowRole.GUARD] == []


def test_a_with_statement_binds_its_target() -> None:
    dug = graph_for(
        "def handle(path):\n    with open(path) as handle:\n        return handle.read()\n"
    )
    names = {node.name for node in dug.nodes.values()}

    assert "handle" in names


def test_a_nested_function_is_a_different_scope() -> None:
    """The unit is the outermost function (D-049); a closure's parameters are bound elsewhere."""
    dug = graph_for(
        "def handle(request):\n    def inner(secret):\n        return secret\n    return inner\n"
    )
    assert {node.name for node in dug.origins()} == {"request"}


def test_path_composition_is_recorded_on_the_definition() -> None:
    dug = graph_for("def handle(name):\n    target = os.path.join(BASE, name)\n")
    composed = [node for node in dug.nodes.values() if node.path_composed]

    assert [node.name for node in composed] == ["target"]


def test_a_bare_use_is_not_path_composition() -> None:
    dug = graph_for("def handle(path):\n    target = path\n")
    assert [node for node in dug.nodes.values() if node.path_composed] == []
