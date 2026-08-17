"""Taint path artifact renderer."""

from typing import Any, Dict, List
from static_agent.contracts import Artifact


def render_taint_path(path_nodes: List[Dict[str, Any]]) -> Artifact:
    """Format ordered list of path nodes into a taint_path Artifact."""
    formatted_chain: List[Dict[str, Any]] = []
    for step in path_nodes:
        formatted_chain.append(
            {
                "line": step.get("line", 1),
                "expr": step.get("expr", ""),
                "var_name": step.get("var_name", ""),
                "role": step.get("role", "propagation"),
            }
        )

    return Artifact(
        artifact_type="taint_path",
        content={
            "length": len(formatted_chain),
            "steps": formatted_chain,
        },
    )
