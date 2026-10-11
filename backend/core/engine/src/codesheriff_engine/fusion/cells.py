"""Which cell of a witness's ratio table applies, given what it said.

This is the seam between fusing and fitting, and it exists so there can only be one answer.
`bayes.py` reads a cell to look a ratio **up**; `calibration/` reads the same cell to count
observations and fit that ratio **in**. Two implementations of "what did this witness say"
would silently fit one quantity and apply another — the ratios would be numerically fine and
would describe a different question than the one being asked, which is the failure mode no
test catches because both halves pass on their own.

The rules are D-005 and D-006, and they are stated once, here:

* A **detection** picks its tier from `raw_score` — the boundaries live in
  `WitnessRatios.for_score` and are mirrored by `TIER_BOUNDARIES` below.
* A **silence** counts only when the witness's `covered_cwes` contains this finding's CWE.
  The taint engine holds no CWE-862 rules whatsoever; letting its silence count there would
  suppress every semantic-only authorisation finding on principle.
* Everything else is `None` — an abstention, a silence about other CWEs, or nothing at all.
  `None` is not a table entry and must never become one: an abstention is exactly 1.0 by
  definition, because an agent that could not look has said nothing about the code, and a
  fitted number there would mean the act of failing carried information.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from codesheriff_contracts import Evidence, EvidenceKind


class RatioCell(StrEnum):
    """A named cell of `WitnessRatios`. The field names, so a fit maps straight onto it."""

    DETECTION_HIGH = "detection_high"
    DETECTION_MEDIUM = "detection_medium"
    DETECTION_LOW = "detection_low"
    SILENCE = "silence"


TIER_BOUNDARIES: tuple[tuple[float, RatioCell], ...] = (
    (0.8, RatioCell.DETECTION_HIGH),
    (0.5, RatioCell.DETECTION_MEDIUM),
)
"""Score at or above which each detection tier applies, strongest first.

Must agree with `WitnessRatios.for_score`, and `test_tiers_agree_with_for_score` holds them
together. Two tier boundaries that drifted apart would fit `detection_high` from observations
that fusion then scores as `detection_medium`.
"""


def tier_for_score(raw_score: float) -> RatioCell:
    """The detection tier a raw score falls in."""
    for floor, cell in TIER_BOUNDARIES:
        if raw_score >= floor:
            return cell
    return RatioCell.DETECTION_LOW


def cell_for(
    cwe: str,
    detections: Iterable[Evidence],
    silences: Iterable[Evidence],
) -> RatioCell | None:
    """The single cell this witness's statements select, or None for no contribution.

    A detection outranks a silence from the same witness: two backends behind one witness
    can disagree, and one backend's silence does not retract its sibling's detection
    (D-011). Where several detections arrive, the strongest tier wins — the same `max`
    that `bayes._contribution` applies to the ratios themselves, since the tiers are
    ordered the same way the ratios are.
    """
    scored = [ev for ev in detections if ev.kind is EvidenceKind.DETECTION]
    if scored:
        return tier_for_score(max(ev.raw_score for ev in scored))

    if any(ev.kind is EvidenceKind.SILENCE and ev.covers(cwe) for ev in silences):
        return RatioCell.SILENCE

    return None
