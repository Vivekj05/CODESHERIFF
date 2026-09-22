"""The taint path artifact — the evidence behind a structural finding.

Every path rendered here is one `networkx` actually found. The superseded engine emitted a
two-element artifact for every source-sink pair it had crossed in a nested loop, with roles
hard-coded to `source` and `sink`, so a `propagation` role could never appear however many steps
the flow really had (`AUDIT.md` 3.2). A reader could not tell a one-hop flow from a five-hop one,
because both rendered identically.

The artifact also carries the sink class and the rule that fired. That is what makes a finding
arguable: "nothing on this path cleared `command`" is a claim a reviewer can check against the
`clears` of the sanitizers they can see, and disagree with.
"""

from __future__ import annotations

from typing import Any

from codesheriff_contracts import Artifact

VALID_ROLES = frozenset({"source", "propagation", "guard", "sink"})


def render_taint_path(
    path_nodes: list[dict[str, Any]],
    sink_class: str = "",
    rule_id: str = "",
) -> Artifact:
    """Format one ordered flow into a `taint_path` artifact.

    `role` is taken from the step rather than defaulted, because the default is what made the old
    artifact unfalsifiable — it claimed `propagation` for steps that were never on a path.
    """
    steps: list[dict[str, Any]] = []
    for step in path_nodes:
        role = str(step.get("role", "propagation"))
        steps.append(
            {
                "line": int(step.get("line", 1)),
                "expr": str(step.get("expr", "")),
                "var_name": str(step.get("var_name", "")),
                "role": role if role in VALID_ROLES else "propagation",
            }
        )

    return Artifact(
        artifact_type="taint_path",
        content={
            "length": len(steps),
            "sink_class": sink_class,
            "rule_id": rule_id,
            "steps": steps,
        },
    )
