"""Def-Use graph construction using NetworkX."""

import re
from typing import Dict, List, Optional, Tuple
import networkx as nx
from pydantic import BaseModel


class DefUseNode(BaseModel):
    node_id: str
    var_name: str
    expr: str
    line: int
    role: str  # "def", "use", "source", "sink", "sanitizer"


class DefUseGraph:
    """NetworkX wrapper for Def-Use data flow graph."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()
        self.nodes: Dict[str, DefUseNode] = {}
        self._counter = 0

    def add_node(self, var_name: str, expr: str, line: int, role: str) -> str:
        self._counter += 1
        node_id = f"n{self._counter}_{var_name}_{line}"
        node_data = DefUseNode(
            node_id=node_id,
            var_name=var_name,
            expr=expr,
            line=line,
            role=role,
        )
        self.nodes[node_id] = node_data
        self.graph.add_node(node_id, **node_data.model_dump())
        return node_id

    def add_edge(self, source_id: str, target_id: str, relation: str = "flow") -> None:
        self.graph.add_edge(source_id, target_id, relation=relation)


def build_defuse_graph(source_code: str, language: str = "python") -> DefUseGraph:
    """Build Def-Use data flow graph from source code."""
    builder = DefUseGraph()
    lines = source_code.splitlines()

    last_def_of: Dict[str, str] = {}

    for line_idx, line_str in enumerate(lines, start=1):
        line = line_str.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue

        # Assignment pattern: var = expr
        assign_match = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+)$", line)
        if assign_match:
            target_var = assign_match.group(1).strip()
            rhs_expr = assign_match.group(2).strip()

            def_id = builder.add_node(target_var, line, line_idx, "def")

            # Find uses in rhs_expr
            used_vars = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", rhs_expr)
            for uvar in set(used_vars):
                if uvar in last_def_of:
                    builder.add_edge(last_def_of[uvar], def_id, relation="data_flow")

            last_def_of[target_var] = def_id

        # Function call / sink execution pattern: function_call(arg1, arg2)
        call_match = re.search(r"([a-zA-Z0-9_\.]+\.execute|[a-zA-Z0-9_\.]+\.system|eval|exec|open)\s*\((.+)\)", line)
        if call_match:
            func_name = call_match.group(1).strip()
            args_str = call_match.group(2).strip()
            call_id = builder.add_node(func_name, line, line_idx, "sink")

            used_vars = re.findall(r"\b([a-zA-Z_][a-zA-Z0-9_]*)\b", args_str)
            for uvar in set(used_vars):
                if uvar in last_def_of:
                    builder.add_edge(last_def_of[uvar], call_id, relation="argument_pass")

    return builder
