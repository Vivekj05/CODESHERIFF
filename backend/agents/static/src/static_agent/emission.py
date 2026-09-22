"""Saying everything a backend found out, not only what it found.

A backend that reaches ten CWEs and detects one has learned two things: that the one is
there, and that the other nine are not. Until Chapter 9 it reported only the first —
`analyze_taint` and `run_semgrep` each returned *either* detections *or* a silence — so
the moment a backend detected anything, its coverage of every other CWE went unstated.

That gap has a cost in the fusion arithmetic. A silence is what lets one witness argue
another's detection down (D-006), and fusion can only apply it if the witness said it. A
unit where the taint engine finds SQL injection and the semantic agent claims command
injection should have the taint engine's silence on CWE-78 pulling that second finding
*down*; with no silence emitted, it contributed exactly nothing.

The contract has always permitted this — a SILENCE and a DETECTION are separate statements
about the same unit, and nothing forbade emitting both. Nothing built them together, which
is the ordinary way a contract goes unused.

The detected CWEs are subtracted, and that subtraction is the point: a SILENCE that still
listed CWE-89 while a DETECTION for CWE-89 sat beside it would have one witness both
alerting on a finding and vouching for it, and `bayes._contribution` would have to break
the tie by rule instead of being handed a coherent statement.
"""

from __future__ import annotations

from codesheriff_contracts import Evidence


def with_residual_silence(
    detections: list[Evidence],
    *,
    agent_id: str,
    agent_version: str,
    unit_id: str,
    covered_cwes: frozenset[str],
    silent_explanation: str,
) -> list[Evidence]:
    """`detections`, plus a SILENCE over the CWEs this backend covered and did not find.

    Returns the detections unchanged when they account for everything the backend can
    reach — a silence over an empty set is not expressible, and would not mean anything
    if it were.
    """
    found = {ev.cwe.strip().upper() for ev in detections if ev.cwe}
    residual = frozenset(covered_cwes) - found
    if not residual:
        return detections

    return [
        *detections,
        Evidence.silence(
            agent_id=agent_id,
            agent_version=agent_version,
            unit_id=unit_id,
            covered_cwes=residual,
            explanation=silent_explanation,
        ),
    ]
