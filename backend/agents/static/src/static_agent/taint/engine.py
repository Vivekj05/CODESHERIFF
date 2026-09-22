"""Taint analysis: propagate over the def-use graph, and report only real paths.

The shape of this module is the whole of `AUDIT.md` 3.1 and 3.2. What it replaces built a def-use
graph, assigned it to a local, never read it, and then computed "taint paths" as a nested loop over
sources and sinks whose only reachability test was `sink_line >= source_line`. No variable was
tracked from one to the other, so an unrelated sink forty lines below a source produced a finding
whose two-step path never contained a propagation step.

Now: seed the origins, run a worklist to a fixpoint, and for each sink ask `networkx` for an actual
path — over a subgraph with the sanitizer edges for *that sink's class* removed, which is what makes
`clears` mean something (`AUDIT.md` 3.4).

The engine never raises. Every failure path returns an abstention with a distinct reason, because an
empty list would be indistinguishable from "analysed, found nothing", which is what SILENCE is for.
"""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from codesheriff_contracts import IN_SCOPE_CWES, ChangeUnit, Evidence
from static_agent.config import StaticConfig
from static_agent.emission import with_residual_silence
from static_agent.scoring import calculate_raw_score
from static_agent.taint.catalog import Catalog, SinkClass
from static_agent.taint.defuse import DefUseGraph, FlowNode, FlowRole, build_defuse_graph
from static_agent.taint.parse import ParseError, UnsupportedLanguageError, language_key, parse
from static_agent.taint.render import render_taint_path

logger = logging.getLogger(__name__)

AGENT_ID = "structural.taint"
AGENT_VERSION = "0.2.0"

MAX_UNIT_BYTES = 400_000
"""Above this the unit abstains rather than being analysed. Oversized units abstain, never
truncate (D-015): a truncated parse produces confident findings from half-read code."""


def _graph_without(dug: DefUseGraph, sink_class: SinkClass) -> nx.DiGraph:
    """The flow graph with every edge that neutralises `sink_class` removed.

    This is the sanitizer model in one function. An `html.escape` edge clears `xss`, so it
    disappears from the graph used to reason about an XSS sink and stays in the one used for a
    command sink — which is exactly the property the old engine lacked, where any sanitizer on any
    line between a source and a sink suppressed the finding whatever the two of them were.
    """
    keep = nx.DiGraph()
    keep.add_nodes_from(dug.graph.nodes)
    for src, dst, data in dug.graph.edges(data=True):
        if sink_class in data.get("clears", frozenset()):
            continue
        keep.add_edge(src, dst)
    return keep


def propagate(dug: DefUseGraph, sink_class: SinkClass) -> dict[str, str]:
    """Worklist propagation: which nodes still carry taint dangerous for `sink_class`.

    Each tainted node maps to the origin its taint came from, which is what lets a path be rendered
    back to where the value entered rather than merely asserted to exist.
    """
    graph = _graph_without(dug, sink_class)
    origin_of: dict[str, str] = {}
    worklist: list[str] = []

    for origin in dug.origins():
        origin_of[origin.node_id] = origin.node_id
        worklist.append(origin.node_id)

    while worklist:
        current = worklist.pop()
        for successor in graph.successors(current):
            if successor in origin_of:
                continue
            origin_of[successor] = origin_of[current]
            worklist.append(successor)

    return origin_of


def _path_between(
    dug: DefUseGraph, sink_class: SinkClass, origin_id: str, sink_id: str
) -> list[str]:
    graph = _graph_without(dug, sink_class)
    try:
        return [str(node) for node in nx.shortest_path(graph, origin_id, sink_id)]
    except (nx.NetworkXNoPath, nx.NodeNotFound):  # pragma: no cover - guarded by propagate()
        return []


def _steps_for(dug: DefUseGraph, path: list[str]) -> list[dict[str, Any]]:
    """The rendered path. The roles are real now: source, propagation..., sink."""
    steps: list[dict[str, Any]] = []
    for position, node_id in enumerate(path):
        node = dug.nodes[node_id]
        if position == 0:
            role = "source"
        elif position == len(path) - 1:
            role = "sink"
        elif node.role is FlowRole.GUARD:
            role = "guard"
        else:
            role = "propagation"
        steps.append({"line": node.line, "expr": node.expr, "var_name": node.name, "role": role})
    return steps


def _path_is_composed(dug: DefUseGraph, path: list[str], sink: FlowNode) -> bool:
    """Whether a base path was joined onto the tainted value somewhere along this flow."""
    return sink.path_composed or any(dug.nodes[node_id].path_composed for node_id in path)


def _findings(unit: ChangeUnit, dug: DefUseGraph) -> dict[str, Evidence]:
    """One Evidence per finding_key, keeping the strongest.

    Keyed rather than appended: with the sink expression gone from `finding_key` (D-004), several
    source-sink pairs in one unit collapse onto one key, and emitting each would apply one agent's
    likelihood ratio several times over for a single finding.
    """
    by_key: dict[str, Evidence] = {}
    propagation_cache: dict[SinkClass, dict[str, str]] = {}

    for sink in dug.sinks():
        rule = sink.sink_rule
        if rule is None or rule.cwe not in IN_SCOPE_CWES:
            # Out of scope is dropped, never relabelled (D-021).
            continue

        if rule.sink_class not in propagation_cache:
            propagation_cache[rule.sink_class] = propagate(dug, rule.sink_class)
        origin_id = propagation_cache[rule.sink_class].get(sink.node_id)
        if origin_id is None:
            continue

        path = _path_between(dug, rule.sink_class, origin_id, sink.node_id)
        if not path:
            continue

        if rule.requires_path_composition and not _path_is_composed(dug, path, sink):
            # A whole path handed in and used as-is is the caller's choice, not a traversal.
            continue

        origin = dug.nodes[origin_id]
        steps = _steps_for(dug, path)
        finding_key = unit.key_for(rule.cwe)
        score = calculate_raw_score(
            danger=rule.danger,
            partial_sanitizer=False,
            path_length=len(steps),
            network_facing=True,
            is_test_file=unit.is_test_file,
        )

        safe_when = f", and {rule.safe_when} is modelled on the sink" if rule.safe_when else ""
        evidence = Evidence.detection(
            agent_id=AGENT_ID,
            agent_version=AGENT_VERSION,
            unit_id=unit.unit_id,
            finding_key=finding_key,
            cwe=rule.cwe,
            raw_score=score,
            confidence=0.90,
            explanation=(
                f"Untrusted value from {origin.origin_rule} at line {origin.line} reaches "
                f"{rule.id} at argument {sink.arg_index} on line {sink.line} through "
                f"{len(steps)} step(s); nothing on the path clears "
                f"{rule.sink_class.value}{safe_when}."
            ),
            artifacts=[render_taint_path(steps, sink_class=rule.sink_class.value, rule_id=rule.id)],
        )
        existing = by_key.get(finding_key)
        if existing is None or evidence.raw_score > existing.raw_score:
            by_key[finding_key] = evidence

    return by_key


def _abstain(unit: ChangeUnit, reason: str, explanation: str) -> list[Evidence]:
    return [
        Evidence.abstention(
            agent_id=AGENT_ID,
            agent_version=AGENT_VERSION,
            unit_id=unit.unit_id,
            reason=reason,
            explanation=explanation,
        )
    ]


def analyze_taint(unit: ChangeUnit, config: StaticConfig) -> list[Evidence]:
    """Flow-based taint analysis of one ChangeUnit. Never raises."""
    try:
        try:
            lang = language_key(unit.language)
        except UnsupportedLanguageError:
            return _abstain(
                unit,
                "language_not_modelled",
                f"structural.taint models Python only; {unit.language} was not analysed.",
            )

        if len(unit.post_src.encode("utf-8")) > MAX_UNIT_BYTES:
            return _abstain(
                unit,
                "unit_too_large",
                f"Unit exceeds {MAX_UNIT_BYTES} bytes; analysing part of it would produce "
                "confident findings from half-read code (D-015).",
            )

        catalog = Catalog.load_from_dir(config.rules_dir)
        if not catalog.sinks.get(lang) or not catalog.sources.get(lang):
            # An empty rule set means the agent could not look. Reporting SILENCE here would tell
            # fusion "I checked and this is clean" on the strength of no rules at all — the single
            # most dangerous thing an agent in this design can say (D-005).
            return _abstain(
                unit,
                "rules_unavailable",
                f"No {lang} sources or sinks loaded from {config.rules_dir}.",
            )

        try:
            root, blob = parse(unit.post_src, lang)
        except ParseError as exc:
            return _abstain(unit, "parse_failed", f"tree-sitter could not parse this unit: {exc}")

        dug = build_defuse_graph(root, blob, catalog, lang)
        by_key = _findings(unit, dug)

        ordered = sorted(by_key.values(), key=lambda e: e.raw_score, reverse=True)
        return with_residual_silence(
            ordered[: config.max_evidence_per_unit],
            agent_id=AGENT_ID,
            agent_version=AGENT_VERSION,
            unit_id=unit.unit_id,
            covered_cwes=catalog.covered_cwes(lang),
            silent_explanation=(
                "Analysed the def-use graph of this unit; no untrusted value reaches a sink of "
                "these classes without being cleared."
            ),
        )

    except Exception as exc:  # never raises (CLAUDE.md, "Agents never raise")
        logger.exception("structural.taint failed on unit %s", unit.unit_id)
        return _abstain(unit, "internal_error", f"{type(exc).__name__}: {exc}")
